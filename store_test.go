package fail2ban

import (
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

func testJail() Jail {
	return Jail{MaxRetry: 3, FindTime: Duration(10 * time.Minute), BanTime: Duration(time.Hour)}
}

func pfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, ok := clientPrefix(netip.MustParseAddr(s))
	if !ok {
		t.Fatalf("clientPrefix(%s) = false", s)
	}
	return p
}

// strikes strikes c n times at at, at+1s, ..., and returns the last result.
func strikes(s *store, c netip.Prefix, j Jail, at time.Time, n int) (Ban, bool) {
	var b Ban
	var ok bool
	for i := range n {
		b, ok = s.strike(c, "probe", j, at.Add(time.Duration(i)*time.Second))
	}
	return b, ok
}

func TestStore_StrikesBan(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	j := testJail()
	if _, ok := s.strike(c, "probe", j, t0); ok {
		t.Fatal("first strike banned")
	}
	if _, ok := s.strike(c, "probe", j, t0.Add(time.Minute)); ok {
		t.Fatal("second strike banned")
	}
	b, ok := s.strike(c, "probe", j, t0.Add(2*time.Minute))
	if !ok {
		t.Fatal("third strike did not ban")
	}
	want := Ban{Prefix: c, Jail: "probe", Until: t0.Add(2*time.Minute + time.Hour), Count: 1}
	if b != want {
		t.Fatalf("ban = %+v, want %+v", b, want)
	}
	if !s.banned(c, t0.Add(2*time.Minute+59*time.Minute+59*time.Second)) {
		t.Fatal("not banned before Until")
	}
	if len(s.counters) != 0 {
		t.Fatalf("counters kept after the ban: %d", len(s.counters))
	}
}

func TestStore_FindTime(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	j := testJail()
	for _, at := range []time.Duration{0, 6 * time.Minute, 11 * time.Minute} {
		if _, ok := s.strike(c, "probe", j, t0.Add(at)); ok {
			t.Fatalf("strike at +%v banned", at)
		}
	}
	if s.banned(c, t0.Add(11*time.Minute)) {
		t.Fatal("banned with two strikes in the window")
	}
}

func TestStore_BanBoundary(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	b, ok := strikes(s, c, testJail(), t0, 3)
	if !ok {
		t.Fatal("no ban")
	}
	if !s.banned(c, b.Until.Add(-time.Nanosecond)) {
		t.Fatal("not banned a moment before Until")
	}
	if s.banned(c, b.Until) {
		t.Fatal("banned at Until")
	}
}

func TestStore_Doubling(t *testing.T) {
	s := newStore(100, 100, 6*time.Hour)
	c := pfx(t, "1.2.3.4")
	j := testJail()
	at := t0
	for i, want := range []struct {
		d     time.Duration
		count int
	}{{time.Hour, 1}, {2 * time.Hour, 2}, {4 * time.Hour, 3}, {6 * time.Hour, 4}, {6 * time.Hour, 5}} {
		b, ok := strikes(s, c, j, at, 3)
		if !ok {
			t.Fatalf("ban %d: none", i+1)
		}
		start := at.Add(2 * time.Second)
		if got := b.Until.Sub(start); got != want.d || b.Count != want.count {
			t.Fatalf("ban %d: length %v count %d, want %v count %d", i+1, got, b.Count, want.d, want.count)
		}
		at = b.Until.Add(time.Hour) // within 24h of its end
	}
	// 25h after the previous ban ended: back to BanTime.
	b, ok := strikes(s, c, j, at.Add(-time.Hour+25*time.Hour), 3)
	if !ok {
		t.Fatal("no ban after 25h")
	}
	if b.Count != 1 || b.Until.Sub(at.Add(-time.Hour+25*time.Hour+2*time.Second)) != time.Hour {
		t.Fatalf("after 25h: %+v, want Count 1 and BanTime", b)
	}
}

func TestStore_Forgive(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	j := testJail()
	strikes(s, c, j, t0, 2)
	s.forgive(c, "probe")
	if _, ok := strikes(s, c, j, t0.Add(time.Minute), 2); ok {
		t.Fatal("banned after forgive")
	}
	if s.banned(c, t0.Add(2*time.Minute)) {
		t.Fatal("banned after forgive")
	}
}

func TestStore_ManualBan(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	b := s.ban(c, "manual", 2*time.Hour, t0, false)
	if b.Until != t0.Add(2*time.Hour) || b.Count != 1 || b.Jail != "manual" {
		t.Fatalf("ban = %+v", b)
	}
	if !s.banned(c, t0.Add(time.Hour)) {
		t.Fatal("not banned")
	}
	next := t0.Add(3 * time.Hour)
	b = s.ban(c, "manual", 2*time.Hour, next, false)
	if b.Until != next.Add(2*time.Hour) || b.Count != 2 {
		t.Fatalf("repeat manual ban = %+v, want 2h and Count 2", b)
	}
	strikes(s, c, testJail(), next.Add(time.Minute), 2) // no-ops: c is banned
	s.unban(c)
	if s.banned(c, next.Add(time.Minute)) {
		t.Fatal("banned after unban")
	}
	if len(s.banRecs) != 0 || len(s.counters) != 0 {
		t.Fatalf("unban left %d records and %d counters", len(s.banRecs), len(s.counters))
	}

	// Unban clears the counters: two strikes before it and one after do not ban.
	d := pfx(t, "5.6.7.8")
	strikes(s, d, testJail(), next, 2)
	s.unban(d)
	if _, ok := s.strike(d, "probe", testJail(), next.Add(time.Minute)); ok {
		t.Fatal("strikes from before unban counted")
	}
}

// A manual ban over a live one keeps the later end.
func TestStore_ManualBanNeverShortens(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	s.ban(c, "manual", 2*time.Hour, t0, false)
	b := s.ban(c, "manual", time.Minute, t0.Add(time.Minute), false)
	if want := t0.Add(2 * time.Hour); !b.Until.Equal(want) {
		t.Fatalf("shorter ban: Until = %v, want %v", b.Until, want)
	}
	if got := s.bans(t0.Add(time.Minute)); len(got) != 1 || !got[0].Until.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("bans() = %+v, want the 2h end", got)
	}
	b = s.ban(c, "manual", 3*time.Hour, t0.Add(time.Minute), false)
	if want := t0.Add(time.Minute + 3*time.Hour); !b.Until.Equal(want) {
		t.Fatalf("longer ban: Until = %v, want %v", b.Until, want)
	}
	checkHeap(t, s)
}

func TestStore_Bounds(t *testing.T) {
	s := newStore(100, 50, 24*time.Hour)
	j := testJail()
	addr := func(i int) netip.Prefix {
		p, _ := clientPrefix(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
		return p
	}
	for i := range 20000 {
		s.strike(addr(i), "probe", j, t0.Add(time.Duration(i)*time.Millisecond))
	}
	if len(s.counters) > 100 || lruLen(t, s) > 100 {
		t.Fatalf("tracked %d (list %d), want ≤ 100", len(s.counters), lruLen(t, s))
	}
	// The most recently struck survive.
	for i := 20000 - 100; i < 20000; i++ {
		if _, ok := s.counters[addr(i)]; !ok {
			t.Fatalf("recent client %d evicted", i)
		}
	}

	s = newStore(100, 50, 24*time.Hour)
	for i := range 20000 {
		// Later bans end later.
		s.ban(addr(i), "manual", time.Hour+time.Duration(i)*time.Second, t0, false)
	}
	live := s.bans(t0)
	if len(live) > 50 || len(s.banRecs) > 50 {
		t.Fatalf("live bans %d, records %d, want ≤ 50", len(live), len(s.banRecs))
	}
	for i := 20000 - 50; i < 20000; i++ {
		if !s.banned(addr(i), t0) {
			t.Fatalf("latest-ending ban %d evicted", i)
		}
	}
	for k := 1; k < len(live); k++ {
		if live[k].Until.Before(live[k-1].Until) {
			t.Fatal("bans not soonest to end first")
		}
	}

	// At the cap, an expired record (kept for doubling) goes before a live ban.
	s = newStore(100, 2, 24*time.Hour)
	s.ban(addr(1), "manual", time.Minute, t0, false)
	s.ban(addr(2), "manual", time.Hour, t0, false)
	later := t0.Add(2 * time.Minute) // addr(1)'s ban has ended
	s.ban(addr(3), "manual", 2*time.Hour, later, false)
	if _, ok := s.banRecs[addr(1)]; ok {
		t.Fatal("expired record kept over a live ban")
	}
	if !s.banned(addr(2), later) || !s.banned(addr(3), later) {
		t.Fatal("live ban evicted while an expired record was there")
	}
}

func TestStore_ConcurrentOneBan(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	j := testJail()
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, ok := s.strike(c, "probe", j, t0); ok {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := wins.Load(); n != 1 {
		t.Fatalf("%d strikes created a ban, want 1", n)
	}
	if !s.banned(c, t0) {
		t.Fatal("not banned")
	}
}

func TestClientPrefix(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1.2.3.4", "1.2.3.4/32"},
		{"::ffff:1.2.3.4", "1.2.3.4/32"},
		{"2001:db8::1", "2001:db8::/64"},
		{"2001:db8::ffff", "2001:db8::/64"},
		{"fe80::1%eth0", "fe80::/64"},
	} {
		got, ok := clientPrefix(netip.MustParseAddr(tc.in))
		if !ok || got != netip.MustParsePrefix(tc.want) {
			t.Errorf("clientPrefix(%s) = %v, %v; want %s", tc.in, got, ok, tc.want)
		}
	}
	if _, ok := clientPrefix(netip.Addr{}); ok {
		t.Error("clientPrefix(zero) = true")
	}
}

func TestStore_Sweep(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	banned := pfx(t, "1.2.3.4")
	struck := pfx(t, "5.6.7.8")
	j := testJail()
	b, _ := strikes(s, banned, j, t0, 3)
	s.strike(struck, "probe", j, t0)
	if len(s.banRecs) != 1 || len(s.counters) != 1 {
		t.Fatalf("before: %d records, %d counters", len(s.banRecs), len(s.counters))
	}

	// After FindTime the idle counter goes; the ended ban's record stays for doubling.
	at := b.Until.Add(time.Minute)
	s.banned(pfx(t, "9.9.9.9"), at)
	if len(s.counters) != 0 || lruLen(t, s) != 0 {
		t.Fatalf("idle counter kept: %d (list %d)", len(s.counters), lruLen(t, s))
	}
	if len(s.banRecs) != 1 {
		t.Fatal("record dropped before end+24h")
	}

	// Less than a minute later no sweep runs, even past end+24h...
	end := b.Until.Add(24 * time.Hour)
	s.swept = end.Add(-30 * time.Second)
	s.banned(pfx(t, "9.9.9.9"), end.Add(time.Second))
	if len(s.banRecs) != 1 {
		t.Fatal("swept twice within a minute")
	}
	// ...and a minute on it does.
	s.banned(pfx(t, "9.9.9.9"), end.Add(time.Minute))
	if len(s.banRecs) != 0 {
		t.Fatalf("record kept past end+24h: %d", len(s.banRecs))
	}
}

func BenchmarkStore_BanAtCap(b *testing.B) {
	const n = 10000
	s := newStore(n, n, 24*time.Hour)
	addr := func(i int) netip.Prefix {
		p, _ := clientPrefix(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
		return p
	}
	for i := range n {
		s.ban(addr(i), "probe", time.Hour+time.Duration(i)*time.Second, t0, false)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ban(addr(n+i%(1<<23)), "probe", 2*time.Hour+time.Duration(i)*time.Second, t0, false)
	}
}

func TestStore_SweepBackwardTime(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	other := pfx(t, "9.9.9.9")
	b := s.ban(c, "manual", time.Minute, t0, false)
	last := b.Until.Add(memory + 10*time.Minute)
	s.swept = last

	// Slightly earlier times, from callers that read the clock before locking,
	// do not sweep and leave swept alone.
	for _, at := range []time.Duration{-time.Second, -30 * time.Second, -time.Minute} {
		s.banned(other, last.Add(at))
		if len(s.banRecs) != 1 || !s.swept.Equal(last) {
			t.Fatalf("at %v: swept (records %d, swept %v)", at, len(s.banRecs), s.swept)
		}
	}
	// A real backward jump, more than a minute, sweeps.
	back := last.Add(-2 * time.Minute)
	s.banned(other, back)
	if len(s.banRecs) != 0 || !s.swept.Equal(back) {
		t.Fatalf("backward jump did not sweep (records %d, swept %v)", len(s.banRecs), s.swept)
	}
}

func TestStore_FindTimeChanges(t *testing.T) {
	s := newStore(100, 100, 24*time.Hour)
	c := pfx(t, "1.2.3.4")
	wide := testJail()
	narrow := wide
	narrow.FindTime = Duration(time.Minute)
	s.strike(c, "probe", wide, t0)
	s.strike(c, "probe", narrow, t0.Add(2*time.Minute))
	if n := len(s.counters[c].strikes["probe"].times); n != 1 {
		t.Fatalf("%d strikes kept, want 1: the older one is outside the new 1m window", n)
	}
	if _, ok := s.strike(c, "probe", narrow, t0.Add(2*time.Minute+time.Second)); ok {
		t.Fatal("banned with the older strike counted")
	}
}

// checkHeap asserts the ban heap holds exactly the records, indexed and ordered.
func checkHeap(t *testing.T, s *store) {
	t.Helper()
	if len(s.byEnd) != len(s.banRecs) {
		t.Fatalf("heap %d records, map %d", len(s.byEnd), len(s.banRecs))
	}
	for i, r := range s.byEnd {
		if r.index != i || s.banRecs[r.prefix] != r {
			t.Fatalf("heap entry %d out of step with the map", i)
		}
		if i > 0 && r.until.Before(s.byEnd[(i-1)/2].until) {
			t.Fatalf("heap order broken at %d", i)
		}
	}
}

func TestStore_HeapInStep(t *testing.T) {
	s := newStore(100, 20, 24*time.Hour)
	addr := func(i int) netip.Prefix {
		p, _ := clientPrefix(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
		return p
	}
	// Bans with scattered ends, re-bans in place, unbans and sweeps.
	for i := range 500 {
		at := t0.Add(time.Duration(i) * time.Minute)
		d := time.Duration((i*7919)%300+1) * time.Minute
		s.ban(addr(i%40), "manual", d, at, i%3 == 0)
		if i%11 == 0 {
			s.unban(addr((i * 13) % 40))
		}
		s.banned(addr(0), at.Add(time.Duration(i%5)*24*time.Hour))
		checkHeap(t, s)
		if len(s.banRecs) > 20 {
			t.Fatalf("%d records over the cap", len(s.banRecs))
		}
	}
}

// lruLen walks s.lru both ways, checks the links agree with each other and
// with s.counters, and returns its length.
func lruLen(t *testing.T, s *store) int {
	t.Helper()
	n := 0
	var prev *client
	for c := s.lru.front; c != nil; c = c.next {
		if c.prev != prev {
			t.Fatalf("lru: %v's prev is not the client before it", c.prefix)
		}
		if s.counters[c.prefix] != c {
			t.Fatalf("lru: %v is not the client s.counters holds", c.prefix)
		}
		prev = c
		n++
	}
	if s.lru.back != prev {
		t.Fatal("lru: back is not the last client")
	}
	return n
}

// The LRU list keeps its links straight through moves and removals at either
// end and in the middle.
func TestClientList(t *testing.T) {
	s := newStore(0, 0, 0)
	cs := make([]*client, 4)
	for i := range cs {
		cs[i] = &client{prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, byte(i)}), 32)}
		s.counters[cs[i].prefix] = cs[i]
		s.lru.pushFront(cs[i]) // front: 3 2 1 0
	}
	order := func() []int {
		var out []int
		for c := s.lru.front; c != nil; c = c.next {
			out = append(out, int(c.prefix.Addr().As4()[3]))
		}
		return out
	}
	s.lru.moveToFront(cs[0]) // 0 3 2 1
	s.lru.moveToFront(cs[2]) // 2 0 3 1
	s.lru.moveToFront(cs[2]) // unchanged
	if got, want := order(), []int{2, 0, 3, 1}; !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
	s.lru.remove(cs[1]) // back
	delete(s.counters, cs[1].prefix)
	s.lru.remove(cs[2]) // front
	delete(s.counters, cs[2].prefix)
	s.lru.remove(cs[0]) // only 3 left after this
	delete(s.counters, cs[0].prefix)
	if got := lruLen(t, s); got != 1 || s.lru.front != cs[3] || s.lru.back != cs[3] {
		t.Fatalf("len = %d, front %v, back %v; want only client 3", got, s.lru.front, s.lru.back)
	}
	s.lru.remove(cs[3])
	if s.lru.front != nil || s.lru.back != nil {
		t.Fatal("emptied list still has an end")
	}
}
