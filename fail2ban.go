// Package fail2ban bans clients that probe or brute-force a site, with the
// standard library alone.
package fail2ban

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// Name is the plugin's name.
const Name = "elagoht/fail2ban"

// version is the plugin's version.
const version = "0.1.0"

// Plugin is the fail2ban plugin.
type Plugin struct {
	opts  Options
	allow []netip.Prefix

	configured bool // whether Configure succeeded
	disabled   bool // development without InDevelopment: nothing happens
	log        *slog.Logger

	now func() time.Time // the clock
}

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
	return host.Use(p.middleware)
}

// Shutdown does nothing: the plugin runs no goroutine.
func (p *Plugin) Shutdown(context.Context) error { return nil }

// middleware is a pass-through until the ban check lands.
func (p *Plugin) middleware(next http.Handler) http.Handler { return next }
