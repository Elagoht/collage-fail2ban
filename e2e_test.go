package fail2ban

import (
	"bytes"
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Elagoht/collage/pkg/collage"
)

// fakeClock is the plugin's clock in these tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// syncBuf is a log sink safe for concurrent writes.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// harness is a real collage app with the plugin first, a page at / that counts
// its renders, a fake clock and a captured log.
type harness struct {
	t       *testing.T
	p       *Plugin
	app     *collage.App
	h       http.Handler
	clock   *fakeClock
	renders *atomic.Int64
	logs    *syncBuf
}

func newApp(t *testing.T, opts Options, dev bool, proxies []string) *harness {
	t.Helper()
	return newAppWith(t, opts, dev, proxies, nil)
}

// newAppWith is newApp, with setup run on the app before its handler is built.
func newAppWith(t *testing.T, opts Options, dev bool, proxies []string, setup func(*collage.App)) *harness {
	t.Helper()
	hs := &harness{
		t:       t,
		p:       New(opts),
		clock:   &fakeClock{t: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)},
		renders: &atomic.Int64{},
		logs:    &syncBuf{},
	}
	hs.p.now = hs.clock.now
	renders := hs.renders
	app, err := collage.New(&collage.Config{
		DevMode: dev,
		Logger:  slog.New(slog.NewTextHandler(hs.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Server:  collage.ServerConfig{Host: "localhost", Port: 3000, TrustedProxies: proxies},
		Template: collage.TemplateConfig{
			FS:    fstest.MapFS{"t/p.html": {Data: []byte(`<p>hi{{count}}</p>`)}},
			Root:  "t",
			Funcs: template.FuncMap{"count": func() string { renders.Add(1); return "" }},
		},
		Plugins: []collage.Plugin{hs.p},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	page := collage.NewPage("home").WithContent(collage.NewFragment("p", "p.html").Build()).WithPath("en", "/").Build()
	if err := app.RegisterPage(page); err != nil {
		t.Fatalf("RegisterPage: %v", err)
	}
	if setup != nil {
		setup(app)
	}
	hs.app = app
	hs.h = app.Handler()
	return hs
}

// get serves target from remote, with X-Forwarded-For lines when given.
func (hs *harness) get(target, remote string, xff ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, r)
	return rec
}

// getDest serves target from remote with a Sec-Fetch-Dest header.
func (hs *harness) getDest(target, remote, dest string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remote
	r.Header.Set("Sec-Fetch-Dest", dest)
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, r)
	return rec
}

// status is the status / gets from remote.
func (hs *harness) status(remote string, xff ...string) int {
	return hs.get("/", remote, xff...).Code
}

// req is a request from remote, for Report and Forgive.
func req(remote string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	r.RemoteAddr = remote
	return r
}

func (hs *harness) probes(n int, remote string) {
	for range n {
		hs.get("/.env", remote)
	}
}

func TestE2E_ProbeBans(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	hs.probes(3, "1.1.1.1:1")
	before := hs.renders.Load()
	rec := hs.get("/", "1.1.1.1:1")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("banned client: status = %d, want 403", rec.Code)
	}
	if got := rec.Body.String(); got != "Forbidden\n" {
		t.Errorf("body = %q, want %q", got, "Forbidden\n")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := hs.renders.Load(); got != before {
		t.Errorf("the banned request rendered the page (%d → %d)", before, got)
	}
	// A banned client's probe is answered 403 too.
	if got := hs.get("/.env", "1.1.1.1:1").Code; got != http.StatusForbidden {
		t.Errorf("banned client's /.env: status = %d, want 403", got)
	}
	if got := hs.status("2.2.2.2:1"); got != http.StatusOK {
		t.Errorf("other client: status = %d, want 200", got)
	}
	if got := hs.renders.Load(); got != before+1 {
		t.Errorf("renders = %d, want %d: the counter must be live", got, before+1)
	}
}

func TestE2E_TwoProbesDoNotBan(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	hs.probes(2, "1.1.1.1:1")
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("status = %d, want 200 after two probes", got)
	}
}

func TestE2E_EarlyRejectionsStrike(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	for _, target := range []string{"/a/../b", "/x%2fy", "/a/./b"} {
		hs.get(target, "1.1.1.1:1")
	}
	if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Errorf("status = %d, want 403", got)
	}
}

// A sloppy doubled slash is redirected by collage, but it is not a probe.
func TestE2E_DoubleSlashIsNotAProbe(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	for range 10 {
		hs.get("/blog//post", "1.1.1.1:1")
	}
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
}

// A probe that is also a 404 strikes probe only; an Off probe jail strikes
// nothing at all.
func TestE2E_ProbeBeatsNotFound(t *testing.T) {
	t.Run("probe only", func(t *testing.T) {
		hs := newApp(t, Options{Jails: map[string]Jail{"notfound": {MaxRetry: 1}}}, false, nil)
		hs.get("/.env", "1.1.1.1:1")
		hs.get("/x%2fy", "1.1.1.1:1")
		if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
			t.Errorf("status = %d, want 200: a probe 404 must not strike notfound", got)
		}
	})
	t.Run("probe off", func(t *testing.T) {
		hs := newApp(t, Options{Jails: map[string]Jail{"probe": {Off: true}, "notfound": {MaxRetry: 1}}}, false, nil)
		hs.probes(5, "1.1.1.1:1")
		if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
			t.Errorf("status = %d, want 200", got)
		}
	})
}

func TestE2E_NotFound(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	for range 49 {
		hs.get("/missing", "1.1.1.1:1")
	}
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Fatalf("after 49 404s: status = %d, want 200", got)
	}
	hs.get("/missing", "1.1.1.1:1")
	if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Errorf("after 50 404s: status = %d, want 403", got)
	}
	b := hs.p.Bans()
	if len(b) != 1 || b[0].Jail != "notfound" {
		t.Errorf("Bans() = %+v, want one notfound ban", b)
	}

	off := newApp(t, Options{Jails: map[string]Jail{"notfound": {Off: true}}}, false, nil)
	for range 60 {
		off.get("/missing", "1.1.1.1:1")
	}
	if got := off.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("notfound off: status = %d, want 200", got)
	}
}

func TestE2E_Report(t *testing.T) {
	t.Run("five ban", func(t *testing.T) {
		hs := newApp(t, Options{}, false, nil)
		for range 5 {
			hs.p.Report(req("1.1.1.1:1"), "login")
		}
		if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
			t.Errorf("status = %d, want 403", got)
		}
	})
	t.Run("forgive resets", func(t *testing.T) {
		hs := newApp(t, Options{}, false, nil)
		for range 4 {
			hs.p.Report(req("1.1.1.1:1"), "login")
		}
		hs.p.Forgive(req("1.1.1.1:1"), "login")
		for range 4 {
			hs.p.Report(req("1.1.1.1:1"), "login")
		}
		if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
			t.Errorf("status = %d, want 200", got)
		}
	})
	t.Run("unknown jail", func(t *testing.T) {
		hs := newApp(t, Options{}, false, nil)
		for range 4 {
			hs.p.Report(req("1.1.1.1:1"), "signup")
		}
		if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
			t.Fatalf("after 4: status = %d, want 200", got)
		}
		hs.p.Report(req("1.1.1.1:1"), "signup")
		if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
			t.Errorf("after 5: status = %d, want 403", got)
		}
		b := hs.p.Bans()
		if len(b) != 1 || b[0].Jail != "signup" || !b[0].Until.Equal(hs.clock.now().Add(15*time.Minute)) {
			t.Errorf("Bans() = %+v, want one signup ban of 15m", b)
		}
	})
}

func TestE2E_TrustedProxy(t *testing.T) {
	hs := newApp(t, Options{}, false, []string{"10.0.0.0/8"})
	for range 3 {
		hs.get("/.env", "10.0.0.1:1", "9.9.9.9")
	}
	if got := hs.status("10.0.0.1:1", "9.9.9.9"); got != http.StatusForbidden {
		t.Errorf("forwarded client: status = %d, want 403", got)
	}
	if got := hs.status("10.0.0.1:1", "8.8.8.8"); got != http.StatusOK {
		t.Errorf("another client through the proxy: status = %d, want 200", got)
	}
	b := hs.p.Bans()
	if len(b) != 1 || b[0].Prefix != netip.MustParsePrefix("9.9.9.9/32") {
		t.Errorf("Bans() = %+v, want only 9.9.9.9/32", b)
	}
}

// Without TrustedProxies, X-Forwarded-For is never read: varying it neither
// dodges the ban nor frames the addresses it names.
func TestE2E_ForgedXFFDoesNotDodge(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	forged := []string{"5.5.5.5", "6.6.6.6", "7.7.7.7"}
	for _, f := range forged {
		hs.get("/.env", "1.1.1.1:1", f)
	}
	if got := hs.status("1.1.1.1:1", "8.8.8.8"); got != http.StatusForbidden {
		t.Errorf("forger: status = %d, want 403", got)
	}
	b := hs.p.Bans()
	if len(b) != 1 || b[0].Prefix != netip.MustParsePrefix("1.1.1.1/32") {
		t.Errorf("Bans() = %+v, want only 1.1.1.1/32", b)
	}
	for _, f := range forged {
		if got := hs.status(f + ":1"); got != http.StatusOK {
			t.Errorf("framed %s: status = %d, want 200", f, got)
		}
	}
}

func TestE2E_Allow(t *testing.T) {
	hs := newApp(t, Options{Allow: []string{"1.1.1.0/24"}}, false, nil)
	hs.probes(10, "1.1.1.1:1")
	for range 5 {
		hs.p.Report(req("1.1.1.1:1"), "login")
	}
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
	// Allow is never banned, by hand either.
	hs.p.Ban(netip.MustParseAddr("1.1.1.1"), time.Hour)
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("after Ban: status = %d, want 200", got)
	}
	if b := hs.p.Bans(); len(b) != 0 {
		t.Errorf("Bans() = %+v, want none", b)
	}
}

// An allowed IPv6 address is matched as itself, not by its /64: it is never
// counted, and a ban of its /64 earned by a neighbour does not block it.
func TestE2E_AllowIPv6Address(t *testing.T) {
	hs := newApp(t, Options{Allow: []string{"2001:db8::1"}}, false, nil)
	hs.probes(5, "[2001:db8::1]:1")
	if b := hs.p.Bans(); len(b) != 0 {
		t.Fatalf("Bans() = %+v, want none", b)
	}
	hs.probes(3, "[2001:db8::2]:1")
	if got := hs.status("[2001:db8::2]:1"); got != http.StatusForbidden {
		t.Errorf("neighbour: status = %d, want 403", got)
	}
	if got := hs.status("[2001:db8::1]:1"); got != http.StatusOK {
		t.Errorf("allowed: status = %d, want 200", got)
	}
}

func TestE2E_IPv6Prefix(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	hs.get("/.env", "[2001:db8::1]:1")
	hs.get("/.env", "[2001:db8::2]:1")
	hs.get("/.env", "[2001:db8::1]:1")
	for _, remote := range []string{"[2001:db8::1]:1", "[2001:db8::2]:1", "[2001:db8::ffff]:1"} {
		if got := hs.status(remote); got != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", remote, got)
		}
	}
	if got := hs.status("[2001:db8:0:1::1]:1"); got != http.StatusOK {
		t.Errorf("another /64: status = %d, want 200", got)
	}
}

func TestE2E_Expiry(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	hs.probes(3, "1.1.1.1:1")
	hs.clock.advance(time.Hour - time.Second)
	if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Fatalf("before the end: status = %d, want 403", got)
	}
	hs.clock.advance(time.Second)
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("after 1h: status = %d, want 200", got)
	}
}

func TestE2E_OnBanOnce(t *testing.T) {
	t.Run("sequential", func(t *testing.T) {
		var mu sync.Mutex
		var got []Ban
		hs := newApp(t, Options{OnBan: func(b Ban) {
			mu.Lock()
			got = append(got, b)
			mu.Unlock()
		}}, false, nil)
		hs.probes(6, "1.1.1.1:1")
		mu.Lock()
		defer mu.Unlock()
		if len(got) != 1 || got[0].Jail != "probe" || got[0].Prefix != netip.MustParsePrefix("1.1.1.1/32") {
			t.Fatalf("OnBan calls = %+v, want exactly one probe ban of 1.1.1.1/32", got)
		}
		if logs := hs.logs.String(); strings.Count(logs, "fail2ban: banned") != 1 ||
			!strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "jail=probe") ||
			!strings.Contains(logs, "client=1.1.1.1/32") || !strings.Contains(logs, "until=") {
			t.Errorf("logs = %q, want one Warn naming client, jail and until", logs)
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		var calls atomic.Int64
		hs := newApp(t, Options{OnBan: func(Ban) { calls.Add(1) }}, false, nil)
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() { hs.get("/.env", "1.1.1.1:1") })
		}
		wg.Wait()
		if n := calls.Load(); n != 1 {
			t.Errorf("OnBan calls = %d, want 1", n)
		}
	})
	t.Run("panic", func(t *testing.T) {
		hs := newApp(t, Options{OnBan: func(Ban) { panic("boom") }}, false, nil)
		hs.probes(3, "1.1.1.1:1")
		if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
			t.Errorf("status = %d, want 403: the ban stands", got)
		}
		logs := hs.logs.String()
		if !strings.Contains(logs, "level=ERROR") || !strings.Contains(logs, "fail2ban: OnBan panicked") || !strings.Contains(logs, "boom") {
			t.Errorf("logs = %q, want the panic at Error", logs)
		}
	})
}

func TestE2E_Development(t *testing.T) {
	var calls atomic.Int64
	hs := newApp(t, Options{OnBan: func(Ban) { calls.Add(1) }}, true, nil)
	hs.probes(10, "1.1.1.1:1")
	for range 10 {
		hs.p.Report(req("1.1.1.1:1"), "login")
	}
	hs.p.Ban(netip.MustParseAddr("1.1.1.1"), time.Hour)
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
	if b := hs.p.Bans(); len(b) != 0 {
		t.Errorf("Bans() = %+v, want none", b)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("OnBan calls = %d, want 0", n)
	}
	hs.p.Unban(netip.MustParseAddr("1.1.1.1"))
	hs.p.Forgive(req("1.1.1.1:1"), "login")
}

func TestE2E_ManualAPI(t *testing.T) {
	var calls atomic.Int64
	hs := newApp(t, Options{OnBan: func(Ban) { calls.Add(1) }}, false, nil)
	addr := netip.MustParseAddr("1.1.1.1")
	hs.p.Ban(addr, 2*time.Hour)
	if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Fatalf("after Ban: status = %d, want 403", got)
	}
	b := hs.p.Bans()
	want := Ban{Prefix: netip.MustParsePrefix("1.1.1.1/32"), Jail: "manual", Until: hs.clock.now().Add(2 * time.Hour), Count: 1}
	if len(b) != 1 || b[0] != want {
		t.Errorf("Bans() = %+v, want [%+v]", b, want)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("OnBan calls = %d, want 1", n)
	}
	if !strings.Contains(hs.logs.String(), "jail=manual") {
		t.Errorf("logs = %q, want the manual ban logged", hs.logs.String())
	}
	hs.p.Unban(addr)
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("after Unban: status = %d, want 200", got)
	}
	if b := hs.p.Bans(); len(b) != 0 {
		t.Errorf("Bans() after Unban = %+v, want none", b)
	}
}

// The public methods run race-free while the app starts.
func TestE2E_BeforeStart(t *testing.T) {
	p := New(Options{})
	app, err := collage.New(&collage.Config{
		Server:   collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{FS: fstest.MapFS{"t/p.html": {Data: []byte(`<p>hi</p>`)}}, Root: "t"},
		Plugins:  []collage.Plugin{p},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	addr := netip.MustParseAddr("1.1.1.1")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			p.Report(req("1.1.1.1:1"), "login")
			p.Forgive(req("1.1.1.1:1"), "login")
			p.Ban(addr, time.Minute)
			p.Unban(addr)
			p.Bans()
		}
	})
	if err := app.Start(); err != nil {
		t.Errorf("Start: %v", err)
	}
	close(stop)
	wg.Wait()
	// A plugin never registered at all is just as safe.
	q := New(Options{})
	q.Report(req("1.1.1.1:1"), "login")
	q.Ban(addr, time.Minute)
	if b := q.Bans(); len(b) != 0 {
		t.Errorf("unstarted Bans() = %+v, want none", b)
	}
}

// A proxy left out of TrustedProxies is RemoteAddr for every visitor: banning
// it would ban them all. Its requests are not counted, and a Warn says why.
func TestE2E_ForgottenTrustedProxies(t *testing.T) {
	hs := newApp(t, Options{}, false, nil)
	for i := range 10 {
		if got := hs.get("/.env", "127.0.0.1:1", "9.9.9.9").Code; got == http.StatusForbidden {
			t.Fatalf("probe %d through an untrusted local proxy: 403, want the proxy never banned", i+1)
		}
	}
	for range 10 {
		r := req("10.0.0.1:1")
		r.Header.Set("X-Forwarded-For", "9.9.9.9")
		hs.p.Report(r, "login")
	}
	if b := hs.p.Bans(); len(b) != 0 {
		t.Errorf("Bans() = %+v, want none", b)
	}
	if n := strings.Count(hs.logs.String(), "TrustedProxies is probably missing"); n != 1 {
		t.Errorf("%d TrustedProxies warnings, want 1; logs:\n%s", n, hs.logs.String())
	}
	// A local client without X-Forwarded-For is still counted.
	hs.probes(3, "127.0.0.2:1")
	if got := hs.status("127.0.0.2:1"); got != http.StatusForbidden {
		t.Errorf("local client without X-Forwarded-For: status = %d, want 403", got)
	}

	trusted := newApp(t, Options{}, false, []string{"127.0.0.1"})
	for range 3 {
		trusted.get("/.env", "127.0.0.1:1", "9.9.9.9")
	}
	if got := trusted.status("127.0.0.1:1", "9.9.9.9"); got != http.StatusForbidden {
		t.Errorf("with TrustedProxies: status = %d, want 403", got)
	}
	if b := trusted.p.Bans(); len(b) != 1 || b[0].Prefix != netip.MustParsePrefix("9.9.9.9/32") {
		t.Errorf("Bans() = %+v, want only 9.9.9.9/32", b)
	}
	if strings.Contains(trusted.logs.String(), "TrustedProxies is probably missing") {
		t.Errorf("warned with TrustedProxies set; logs:\n%s", trusted.logs.String())
	}
}

// A probe path the site really serves as a page is not a probe; a handler or a
// mount serving it still is.
func TestE2E_ProbePathOnARealRoute(t *testing.T) {
	page := newAppWith(t, Options{}, false, nil, func(app *collage.App) {
		cgi := collage.NewPage("cgi").WithContent(collage.NewFragment("p", "p.html").Build()).WithPath("en", "/cgi-bin/x").Build()
		if err := app.RegisterPage(cgi); err != nil {
			t.Fatalf("RegisterPage: %v", err)
		}
	})
	for i := range 4 {
		if got := page.get("/cgi-bin/x", "1.1.1.1:1").Code; got != http.StatusOK {
			t.Fatalf("page at /cgi-bin/x, request %d: status = %d, want 200", i+1, got)
		}
	}
	if b := page.p.Bans(); len(b) != 0 {
		t.Errorf("page: Bans() = %+v, want none", b)
	}

	handler := newAppWith(t, Options{}, false, nil, func(app *collage.App) {
		if err := app.Handle("/cgi-bin/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		})); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	})
	for range 3 {
		handler.get("/cgi-bin/x", "1.1.1.1:1")
	}
	if got := handler.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Errorf("handler at /cgi-bin/: status = %d, want 403", got)
	}
}

// A missing file under a mount is a broken link on a page, not a scan.
func TestE2E_MountNotFoundNotCounted(t *testing.T) {
	hs := newAppWith(t, Options{}, false, nil, func(app *collage.App) {
		if err := app.Mount("/static/", fstest.MapFS{"app.css": {Data: []byte("a")}}); err != nil {
			t.Fatalf("Mount: %v", err)
		}
	})
	for range 60 {
		if got := hs.get("/static/missing.png", "1.1.1.1:1").Code; got != http.StatusNotFound {
			t.Fatalf("missing static file: status = %d, want 404", got)
		}
	}
	if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("status = %d, want 200", got)
	}
}

// <img src="/.env"> on another page must not ban its readers; a document
// request is still judged.
func TestE2E_SubresourceRequestsNotCounted(t *testing.T) {
	for _, dest := range []string{"image", "script", "style", "font"} {
		hs := newApp(t, Options{Jails: map[string]Jail{"notfound": {MaxRetry: 1}}}, false, nil)
		for range 3 {
			hs.getDest("/.env", "1.1.1.1:1", dest)
		}
		hs.getDest("/missing", "1.1.1.1:1", dest)
		if got := hs.status("1.1.1.1:1"); got != http.StatusOK {
			t.Errorf("Sec-Fetch-Dest %s: status = %d, want 200", dest, got)
		}
	}
	for _, dest := range []string{"document", "iframe", "empty"} {
		hs := newApp(t, Options{}, false, nil)
		for range 3 {
			hs.getDest("/.env", "1.1.1.1:1", dest)
		}
		if got := hs.status("1.1.1.1:1"); got != http.StatusForbidden {
			t.Errorf("Sec-Fetch-Dest %s: status = %d, want 403", dest, got)
		}
	}
}

// Ban with no length does nothing; a manual ban never shortens a live one.
func TestE2E_BanLength(t *testing.T) {
	var calls atomic.Int64
	hs := newApp(t, Options{OnBan: func(Ban) { calls.Add(1) }}, false, nil)
	addr := netip.MustParseAddr("1.1.1.1")
	hs.p.Ban(addr, 0)
	hs.p.Ban(addr, -time.Hour)
	if b := hs.p.Bans(); len(b) != 0 {
		t.Errorf("Bans() after Ban(0) and Ban(-1h) = %+v, want none", b)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("OnBan calls = %d, want 0", n)
	}
	if strings.Contains(hs.logs.String(), "fail2ban: banned") {
		t.Errorf("Ban(0) logged a ban: %s", hs.logs.String())
	}

	hs.p.Ban(addr, 2*time.Hour)
	hs.p.Ban(addr, time.Minute)
	b := hs.p.Bans()
	if len(b) != 1 || !b[0].Until.Equal(hs.clock.now().Add(2*time.Hour)) {
		t.Fatalf("Bans() = %+v, want the 2h ban kept", b)
	}
	hs.p.Ban(addr, 3*time.Hour)
	if b := hs.p.Bans(); len(b) != 1 || !b[0].Until.Equal(hs.clock.now().Add(3*time.Hour)) {
		t.Errorf("Bans() = %+v, want the ban lengthened to 3h", b)
	}
}

// A request from another site — a no-cors fetch, a hidden iframe, a link —
// never strikes; a same-origin document request is still judged.
func TestE2E_CrossSiteRequestsNotCounted(t *testing.T) {
	send := func(hs *harness, site, dest string) {
		for range 3 {
			r := httptest.NewRequest(http.MethodGet, "/.env", nil)
			r.RemoteAddr = "1.1.1.1:1"
			r.Header.Set("Sec-Fetch-Site", site)
			r.Header.Set("Sec-Fetch-Dest", dest)
			hs.h.ServeHTTP(httptest.NewRecorder(), r)
		}
	}
	cross := newApp(t, Options{}, false, nil)
	send(cross, "cross-site", "empty")
	if got := cross.status("1.1.1.1:1"); got != http.StatusOK {
		t.Errorf("cross-site: status = %d, want 200", got)
	}
	same := newApp(t, Options{}, false, nil)
	send(same, "same-origin", "document")
	if got := same.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Errorf("same-origin document: status = %d, want 403", got)
	}
}

// missingPage registers a page at path whose Required fragment answers
// ErrNotFound, so the page routes but answers 404.
func missingPage(t *testing.T, app *collage.App, name, path string) {
	t.Helper()
	frag := collage.NewFragment(name, "p.html").
		WithData(collage.Load(func(context.Context, *collage.RenderContext) (string, error) {
			return "", collage.ErrNotFound
		})).Required().Build()
	if err := app.RegisterPage(collage.NewPage(name).WithPath("en", path).WithContent(frag).Build()); err != nil {
		t.Fatalf("RegisterPage %s: %v", path, err)
	}
}

// A placeholder page that answers 404 for a probe path does not serve it: the
// probe still counts. Core records the page as the route before it renders.
func TestE2E_ProbeAPageAnswers404StillCounts(t *testing.T) {
	stories := newAppWith(t, Options{}, false, nil, func(app *collage.App) {
		missingPage(t, app, "story", "/stories/{id}")
	})
	for range 3 {
		if got := stories.get("/stories/.env", "1.1.1.1:1").Code; got != http.StatusNotFound {
			t.Fatalf("/stories/.env: status = %d, want 404 from the page", got)
		}
	}
	if got := stories.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Errorf("/stories/{id} answering 404: status = %d, want 403", got)
	}

	root := newAppWith(t, Options{}, false, nil, func(app *collage.App) {
		missingPage(t, app, "slug", "/{slug}")
	})
	for range 3 {
		if got := root.get("/.env", "1.1.1.1:1").Code; got != http.StatusNotFound {
			t.Fatalf("/.env: status = %d, want 404 from the page", got)
		}
	}
	if got := root.status("1.1.1.1:1"); got != http.StatusForbidden {
		t.Errorf("/{slug} answering 404: status = %d, want 403", got)
	}
}

// With TrustedProxies right, X-Forwarded-For naming only the proxy itself is
// not the forgotten-proxy case: no Warn, and the request counts.
func TestE2E_ForgottenProxyGuardNeedsAnotherAddress(t *testing.T) {
	for _, proxies := range [][]string{{"127.0.0.1"}, nil} {
		hs := newApp(t, Options{}, false, proxies)
		for range 3 {
			hs.get("/.env", "127.0.0.1:1", "127.0.0.1")
		}
		if strings.Contains(hs.logs.String(), "TrustedProxies is probably missing") {
			t.Errorf("TrustedProxies %v: warned for X-Forwarded-For naming the proxy itself", proxies)
		}
		if got := hs.status("127.0.0.1:1"); got != http.StatusForbidden {
			t.Errorf("TrustedProxies %v: status = %d, want 403: the request counts", proxies, got)
		}
	}
}
