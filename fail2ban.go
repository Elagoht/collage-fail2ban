// Package fail2ban bans clients that probe or brute-force a site, with the
// standard library alone.
package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
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

	// proxyWarning logs, once, that a local proxy's requests are not counted
	// because Server.TrustedProxies does not list it.
	proxyWarning sync.Once
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

// counted is the client r comes from, and whether its requests are counted.
// Beyond client's rules, a request from a loopback or private RemoteAddr that
// carries X-Forwarded-For but whose ClientIP is still RemoteAddr is not: that
// is a proxy Server.TrustedProxies forgot, and banning it would ban every
// visitor behind it. The first such request logs a Warn.
func (p *Plugin) counted(r *http.Request) (netip.Prefix, bool) {
	addr := collage.ClientIP(r)
	if len(r.Header.Values("X-Forwarded-For")) > 0 && (addr.IsLoopback() || addr.IsPrivate()) && addr == remoteAddr(r) {
		p.proxyWarning.Do(func() {
			p.log.LogAttrs(r.Context(), slog.LevelWarn,
				"fail2ban: a request from a local proxy carries X-Forwarded-For, but Server.TrustedProxies is probably missing it; requests through it are not counted, or the proxy, and every visitor with it, would be banned",
				slog.String("proxy", addr.String()))
		})
		return netip.Prefix{}, false
	}
	return p.clientOf(addr)
}

// remoteAddr is r.RemoteAddr's host, with or without a port, unmapped and
// without its zone; the zero Addr when it holds none.
func remoteAddr(r *http.Request) netip.Addr {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap().WithZone("")
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

// OnRequest judges the request once it is answered: a probe path the site
// does not serve as a page, a document or an action, or an early rejection,
// strikes the probe jail; else a 404 not from a mount strikes notfound. A
// browser's subresource or cross-site request strikes nothing. The request is classified
// here, before anything downstream can change it; finish only hears the status
// and reads the route the request resolved to.
func (p *Plugin) OnRequest(r *http.Request) (context.Context, func(status int)) {
	ctx := r.Context()
	if !p.started.Load() || isSubresource(r) {
		return ctx, nil
	}
	c, ok := p.counted(r)
	if !ok {
		return ctx, nil
	}
	probePath := isProbe(r, p.probes)
	early := isEarlyRejection(r)
	return ctx, func(status int) {
		// The route is known only now: routing fills it in after OnRequest.
		kind, _ := collage.RouteOf(ctx)
		switch {
		case probePath && !servesPath(kind), early:
			p.strike(c, "probe")
		case status == http.StatusNotFound && kind != "mount":
			p.strike(c, "notfound")
		}
	}
}

// servesPath reports whether a route of kind is the site's own content at its
// path — a page, a document or an action — so a probe path resolving to it is
// one the site really serves. A handler or a mount answers a whole prefix, so a
// probe under it still counts.
func servesPath(kind string) bool {
	switch kind {
	case "page", "document", "action":
		return true
	}
	return false
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
	if c, ok := p.counted(r); ok {
		p.strike(c, jail)
	}
}

// Forgive clears r's client's strikes in jail. It is only safe when the
// success proves the failures were the same person's — a login to the very
// account being guessed: forgiving on any success lets an attacker with an
// account of their own guess without limit.
func (p *Plugin) Forgive(r *http.Request, jail string) {
	if !p.started.Load() {
		return
	}
	if c, ok := p.client(r); ok {
		p.store.forgive(c, jail)
	}
}

// Ban bans addr's client for d, in jail "manual", without doubling. A d of zero
// or less does nothing, and a live ban ending later keeps its end: Ban never
// shortens a ban. An address in Allow is never banned.
func (p *Plugin) Ban(addr netip.Addr, d time.Duration) {
	if !p.started.Load() || d <= 0 {
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
