package fail2ban_test

import (
	"bytes"
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	fail2ban "github.com/Elagoht/collage-fail2ban"
	"github.com/Elagoht/collage/pkg/collage"
)

// buildReader reads a finished build, as elagoht/deploy does; with one
// registered, the build asks the handler for every file to capture its headers.
type buildReader struct{ files []collage.BuiltFile }

func (*buildReader) Name() string                             { return "test/buildreader" }
func (*buildReader) Version() string                          { return "0" }
func (*buildReader) Init(context.Context, collage.Host) error { return nil }
func (*buildReader) Shutdown(context.Context) error           { return nil }
func (b *buildReader) OnBuildFinished(_ context.Context, ev *collage.BuildFinishedEvent) error {
	b.files = ev.Files
	return nil
}

// lockedBuf is a log sink safe for concurrent writes.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *lockedBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *lockedBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureAddr is the address a capture request comes from: httptest's.
var captureAddr = netip.MustParseAddr("192.0.2.1")

// buildSite builds a site with the plugin first: a page at / and a mount at
// /static/ whose three files are probe paths, under a probe jail that bans at
// the first strike. When banFirst is set, the page's render bans captureAddr,
// so it is banned before the build asks for anything.
func buildSite(t *testing.T, banFirst bool) (*fail2ban.Plugin, *buildReader, *lockedBuf, *int) {
	t.Helper()
	var mu sync.Mutex
	onBan := 0
	f2b := fail2ban.New(fail2ban.Options{
		ProbePaths: []string{"/static/"},
		Jails:      map[string]fail2ban.Jail{"probe": {MaxRetry: 1, FindTime: fail2ban.Duration(time.Hour), BanTime: fail2ban.Duration(time.Hour)}},
		OnBan: func(fail2ban.Ban) {
			mu.Lock()
			defer mu.Unlock()
			onBan++
		},
	})
	reader := &buildReader{}
	logs := &lockedBuf{}
	app, err := collage.New(&collage.Config{
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Server: collage.ServerConfig{Host: "localhost", Port: 3000},
		Template: collage.TemplateConfig{
			FS:   fstest.MapFS{"t/p.html": {Data: []byte(`<main>home{{ban}}</main>`)}},
			Root: "t",
			Funcs: template.FuncMap{"ban": func() string {
				if banFirst {
					f2b.Ban(captureAddr, time.Hour)
				}
				return ""
			}},
		},
		Plugins: []collage.Plugin{f2b, reader},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := collage.NewPage("home").WithContent(collage.NewFragment("home", "p.html").Build()).WithPath("en", "/").Build()
	if err := app.RegisterPage(page); err != nil {
		t.Fatal(err)
	}
	if err := app.Mount("/static/", fstest.MapFS{
		"a.css": {Data: []byte("a{}")},
		"b.css": {Data: []byte("b{}")},
		"c.css": {Data: []byte("c{}")},
	}); err != nil {
		t.Fatal(err)
	}
	builder, err := collage.NewBuilder(app, collage.BuildOptions{OutDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	report, err := builder.Build(context.Background())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, f := range report.Findings {
		t.Errorf("finding: %s %s: %s", f.Rule, f.Path, f.Message)
	}
	mu.Lock()
	defer mu.Unlock()
	n := onBan
	return f2b, reader, logs, &n
}

// checkCaptured fails unless the page and the three mount files were captured,
// each answered 200.
func checkCaptured(t *testing.T, reader *buildReader) {
	t.Helper()
	want := map[string]bool{"/": false, "/static/a.css": false, "/static/b.css": false, "/static/c.css": false}
	for _, f := range reader.files {
		if !f.Captured {
			continue
		}
		if _, ok := want[f.Path]; ok {
			want[f.Path] = true
		}
		if f.Status != http.StatusOK {
			t.Errorf("%s: status %d", f.Path, f.Status)
		}
	}
	for path, seen := range want {
		if !seen {
			t.Errorf("%s was not captured", path)
		}
	}
}

// A static build's header capture is not a client: asking for files under a
// probe path strikes nothing, bans nobody and logs no ban.
func TestBuildCaptureDoesNotStrike(t *testing.T) {
	f2b, reader, logs, onBan := buildSite(t, false)
	checkCaptured(t, reader)
	if bans := f2b.Bans(); len(bans) != 0 {
		t.Errorf("Bans() = %+v, want none", bans)
	}
	if *onBan != 0 {
		t.Errorf("OnBan called %d times", *onBan)
	}
	if strings.Contains(logs.String(), "fail2ban: banned") {
		t.Errorf("a ban was logged:\n%s", logs)
	}
}

// Nor is a capture refused when its address is banned: the build's answer is
// the file's, not a banned client's 403.
func TestBuildCaptureIsNotRefused(t *testing.T) {
	_, reader, _, _ := buildSite(t, true)
	checkCaptured(t, reader)
}
