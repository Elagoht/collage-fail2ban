package fail2ban

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// build runs collage.New with the plugin, and the plugin's JSON section when
// raw is not empty; the error is Configure's.
func build(t *testing.T, p *Plugin, dev bool, raw string) error {
	t.Helper()
	cfg := &collage.Config{
		Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
		DevMode:  dev,
		Template: collage.TemplateConfig{FS: fstest.MapFS{"t/p.html": {Data: []byte(`<p>hi</p>`)}}, Root: "t"},
		Plugins:  []collage.Plugin{p},
	}
	if raw != "" {
		cfg.PluginConfig = map[string]json.RawMessage{Name: json.RawMessage(raw)}
	}
	_, err := collage.New(cfg)
	return err
}

func TestJail_Defaults(t *testing.T) {
	tests := []struct {
		name string
		o    Options
		jail string
		want Jail
	}{
		{"probe", Options{}, "probe", Jail{3, Duration(10 * time.Minute), Duration(time.Hour), false}},
		{"notfound", Options{}, "notfound", Jail{50, Duration(time.Minute), Duration(10 * time.Minute), false}},
		{"app jail", Options{}, "login", Jail{5, Duration(10 * time.Minute), Duration(15 * time.Minute), false}},
		{"override one field", Options{Jails: map[string]Jail{"probe": {BanTime: Duration(6 * time.Hour)}}}, "probe",
			Jail{3, Duration(10 * time.Minute), Duration(6 * time.Hour), false}},
		{"off", Options{Jails: map[string]Jail{"notfound": {Off: true}}}, "notfound",
			Jail{50, Duration(time.Minute), Duration(10 * time.Minute), true}},
		{"app jail override", Options{Jails: map[string]Jail{"login": {MaxRetry: 2}}}, "login",
			Jail{2, Duration(10 * time.Minute), Duration(15 * time.Minute), false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.o.jail(tt.jail); got != tt.want {
				t.Errorf("jail(%q) = %+v, want %+v", tt.jail, got, tt.want)
			}
		})
	}
}

func TestConfigure_JSON(t *testing.T) {
	p := New(Options{})
	raw := `{"jails":{"probe":{"banTime":"6h"}},"maxBanTime":"48h","allow":["10.0.0.0/8","192.0.2.7","::ffff:198.51.100.1"]}`
	if err := build(t, p, false, raw); err != nil {
		t.Fatal(err)
	}
	if got := p.opts.jail("probe").BanTime; got != Duration(6*time.Hour) {
		t.Errorf("probe banTime = %v", time.Duration(got))
	}
	if p.opts.MaxBanTime != Duration(48*time.Hour) {
		t.Errorf("maxBanTime = %v", time.Duration(p.opts.MaxBanTime))
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.7/32"),
		netip.MustParsePrefix("198.51.100.1/32"),
	}
	if len(p.allow) != len(want) {
		t.Fatalf("allow = %v", p.allow)
	}
	for i := range want {
		if p.allow[i] != want[i] {
			t.Errorf("allow[%d] = %v, want %v", i, p.allow[i], want[i])
		}
	}
}

func TestConfigure_NanosecondDuration(t *testing.T) {
	p := New(Options{})
	if err := build(t, p, false, `{"maxBanTime":3600000000000}`); err != nil {
		t.Fatal(err)
	}
	if p.opts.MaxBanTime != Duration(time.Hour) {
		t.Errorf("maxBanTime = %v", time.Duration(p.opts.MaxBanTime))
	}
}

func TestConfigure_Invalid(t *testing.T) {
	neg := func(j Jail) Options { return Options{Jails: map[string]Jail{"probe": j}} }
	tests := map[string]struct {
		o        Options
		contains string
	}{
		"allow entry":      {Options{Allow: []string{"nope"}}, "nope"},
		"allow bad prefix": {Options{Allow: []string{"10.0.0.0/99"}}, "10.0.0.0/99"},
		"maxRetry":         {neg(Jail{MaxRetry: -1}), "maxRetry"},
		"findTime":         {neg(Jail{FindTime: -1}), "findTime"},
		"banTime":          {neg(Jail{BanTime: -1}), "banTime"},
		"maxBanTime":       {Options{MaxBanTime: -1}, "maxBanTime"},
		"maxTracked":       {Options{MaxTracked: -1}, "maxTracked"},
		"maxBans":          {Options{MaxBans: -1}, "maxBans"},
		"probePaths":       {Options{ProbePaths: []string{"admin"}}, "admin"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := build(t, New(tt.o), false, "")
			if err == nil {
				t.Fatal("want a start error")
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Errorf("error %q does not contain %q", err, tt.contains)
			}
		})
	}
}

func TestConfigure_Defaults(t *testing.T) {
	p := New(Options{})
	if err := build(t, p, false, ""); err != nil {
		t.Fatal(err)
	}
	o := p.opts
	if o.MaxBanTime != Duration(24*time.Hour) || o.MaxTracked != 10000 || o.MaxBans != 10000 {
		t.Errorf("defaults = %v / %d / %d", time.Duration(o.MaxBanTime), o.MaxTracked, o.MaxBans)
	}
	if p.disabled {
		t.Error("disabled outside development")
	}
	if p.now == nil {
		t.Error("no clock")
	}
}

func TestConfigure_Development(t *testing.T) {
	p := New(Options{})
	if err := build(t, p, true, ""); err != nil {
		t.Fatal(err)
	}
	if !p.disabled {
		t.Error("development without InDevelopment must disable the plugin")
	}
	p = New(Options{InDevelopment: true})
	if err := build(t, p, true, ""); err != nil {
		t.Fatal(err)
	}
	if p.disabled {
		t.Error("InDevelopment must enable the plugin")
	}
}

// useSpy wraps the real host the app hands Init, counting calls to Use.
type useSpy struct {
	collage.Host
	uses int
}

func (h *useSpy) Use(mw func(http.Handler) http.Handler) error {
	h.uses++
	return h.Host.Use(mw)
}

// spyPlugin runs the plugin's Init against a useSpy.
type spyPlugin struct {
	*Plugin
	spy *useSpy
}

func (s *spyPlugin) Init(ctx context.Context, host collage.Host) error {
	s.spy = &useSpy{Host: host}
	return s.Plugin.Init(ctx, s.spy)
}

func TestInit_UseOnlyWhenEnabled(t *testing.T) {
	for _, dev := range []bool{false, true} {
		p := New(Options{})
		sp := &spyPlugin{Plugin: p}
		app, err := collage.New(&collage.Config{
			Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
			DevMode:  dev,
			Template: collage.TemplateConfig{FS: fstest.MapFS{"t/p.html": {Data: []byte(`<p>hi</p>`)}}, Root: "t"},
			Plugins:  []collage.Plugin{sp},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := app.Start(); err != nil {
			t.Fatal(err)
		}
		if want := !dev; (sp.spy.uses == 1) != want {
			t.Errorf("dev=%v: Use called %d times", dev, sp.spy.uses)
		}
		if p.log == nil {
			t.Errorf("dev=%v: no logger", dev)
		}
	}
}
