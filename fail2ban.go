// Package fail2ban bans clients that probe or brute-force a site, with the
// standard library alone.
package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// Name is the plugin's name.
const Name = "elagoht/fail2ban"

// version is the plugin's version.
const version = "0.1.0"

// Plugin is the fail2ban plugin.
type Plugin struct {
	opts   Options
	allow  []netip.Prefix
	probes []string // probe path prefixes, lower-cased

	configured bool // whether Configure succeeded
	disabled   bool // development without InDevelopment: nothing happens
	log        *slog.Logger

	now func() time.Time // the clock

	store *store
	// started is set last in Init, once store and log are in place; every
	// public method and the request hook check it first, so before Init and in
	// development they do nothing, race-free.
	started atomic.Bool
}

var _ collage.RequestHook = (*Plugin)(nil)

// New returns the plugin.
func New(opts Options) *Plugin { return &Plugin{opts: opts, now: time.Now} }

// Name returns Name.
func (p *Plugin) Name() string { return Name }

// Version returns the plugin's version.
func (p *Plugin) Version() string { return version }

// Configure reads the configuration, checks it, parses Allow and applies the
// defaults.
func (p *Plugin) Configure(_ context.Context, host collage.ConfigHost) error {
	if err := host.Config(&p.opts); err != nil {
		return err
	}
	o := &p.opts
	if err := o.validate(); err != nil {
		return err
	}
	allow, err := parseAllow(o.Allow)
	if err != nil {
		return err
	}
	p.allow = allow
	p.probes = probePrefixes(o.ProbePaths)
	p.disabled = host.DevMode() && !o.InDevelopment
	if o.MaxBanTime == 0 {
		o.MaxBanTime = Duration(defaultMaxBanTime)
	}
	if o.MaxTracked == 0 {
		o.MaxTracked = defaultMaxTracked
	}
	if o.MaxBans == 0 {
		o.MaxBans = defaultMaxBans
	}
	if p.now == nil {
		p.now = time.Now
	}
	p.configured = true
	return nil
}

// Init stores the host's logger and, unless the plugin is disabled, installs
// its middleware.
func (p *Plugin) Init(_ context.Context, host collage.Host) error {
	if !p.configured {
		return errors.New("fail2ban: register the plugin in Config.Plugins, where Configure runs")
	}
	p.log = host.Logger()
	if p.disabled {
		return nil
	}
	if err := host.Use(p.middleware); err != nil {
		return err
	}
	o := p.opts
	p.store = newStore(o.MaxTracked, o.MaxBans, time.Duration(o.MaxBanTime))
	p.started.Store(true)
	return nil
}

// Shutdown does nothing: the plugin runs no goroutine.
func (p *Plugin) Shutdown(context.Context) error { return nil }

// client is the client r comes from, and whether it is one to count: not the
// zero address, and not in Allow.
func (p *Plugin) client(r *http.Request) (netip.Prefix, bool) {
	return p.clientOf(collage.ClientIP(r))
}

// clientOf is the client addr belongs to, and whether it is one to count.
// Allow is matched against the address itself, so an allowed IPv6 address is
// not taken for its whole /64.
func (p *Plugin) clientOf(addr netip.Addr) (netip.Prefix, bool) {
	c, ok := clientPrefix(addr)
	if !ok {
		return netip.Prefix{}, false
	}
	a := addr.Unmap().WithZone("")
	for _, pfx := range p.allow {
		if pfx.Contains(a) {
			return netip.Prefix{}, false
		}
	}
	return c, true
}

// OnRequest judges the request once it is answered: a probe path or an early
// rejection strikes the probe jail, else a 404 strikes notfound. The request is
// classified here, before anything downstream can change it; finish only
// hears the status.
func (p *Plugin) OnRequest(r *http.Request) (context.Context, func(status int)) {
	ctx := r.Context()
	if !p.started.Load() {
		return ctx, nil
	}
	c, ok := p.client(r)
	if !ok {
		return ctx, nil
	}
	probe := isProbe(r, p.probes) || isEarlyRejection(r)
	return ctx, func(status int) {
		switch {
		case probe:
			p.strike(c, "probe")
		case status == http.StatusNotFound:
			p.strike(c, "notfound")
		}
	}
}

// strike counts one strike against c in jail and announces the ban it makes.
func (p *Plugin) strike(c netip.Prefix, jail string) {
	if b, ok := p.store.strike(c, jail, p.opts.jail(jail), p.now()); ok {
		p.announce(b)
	}
}

// announce logs a new ban and calls OnBan, recovering its panic: the ban
// stands either way. It runs after the store's lock is released.
func (p *Plugin) announce(b Ban) {
	ctx := context.Background()
	p.log.LogAttrs(ctx, slog.LevelWarn, "fail2ban: banned",
		slog.String("client", b.Prefix.String()),
		slog.String("jail", b.Jail),
		slog.Time("until", b.Until))
	if p.opts.OnBan == nil {
		return
	}
	defer func() {
		if v := recover(); v != nil {
			p.log.LogAttrs(ctx, slog.LevelError, "fail2ban: OnBan panicked",
				slog.String("client", b.Prefix.String()),
				slog.String("panic", fmt.Sprint(v)))
		}
	}()
	p.opts.OnBan(b)
}

// Report strikes r's client in jail: a failed login, say. A jail without
// settings of its own bans at 5 strikes in 10 minutes, for 15 minutes.
func (p *Plugin) Report(r *http.Request, jail string) {
	if !p.started.Load() {
		return
	}
	if c, ok := p.client(r); ok {
		p.strike(c, jail)
	}
}

// Forgive clears r's client's strikes in jail: after a successful login, say.
func (p *Plugin) Forgive(r *http.Request, jail string) {
	if !p.started.Load() {
		return
	}
	if c, ok := p.client(r); ok {
		p.store.forgive(c, jail)
	}
}

// Ban bans addr's client for d, in jail "manual", without doubling. An address
// in Allow is never banned.
func (p *Plugin) Ban(addr netip.Addr, d time.Duration) {
	if !p.started.Load() {
		return
	}
	if c, ok := p.clientOf(addr); ok {
		p.announce(p.store.ban(c, "manual", d, p.now(), false))
	}
}

// Unban lifts addr's client's ban and forgets its strikes and earlier bans.
func (p *Plugin) Unban(addr netip.Addr) {
	if !p.started.Load() {
		return
	}
	if c, ok := clientPrefix(addr); ok {
		p.store.unban(c)
	}
}

// Bans returns the live bans, soonest to end first.
func (p *Plugin) Bans() []Ban {
	if !p.started.Load() {
		return nil
	}
	return p.store.bans(p.now())
}

// middleware answers a banned client with a plain 403 and renders nothing, so
// a flood of banned requests stays cheap.
func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.started.Load() {
			if c, ok := p.client(r); ok && p.store.banned(c, p.now()) {
				h := w.Header()
				h.Set("Content-Type", "text/plain; charset=utf-8")
				h.Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, "Forbidden\n")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
