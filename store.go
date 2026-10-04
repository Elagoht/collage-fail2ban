package fail2ban

import (
	"net/netip"
	"slices"
	"sync"
	"time"
)

// memory is how long a ban record outlives its ban, so a repeat offender's
// next ban doubles.
const memory = 24 * time.Hour

// sweepEvery is the least time between two sweeps.
const sweepEvery = time.Minute

// store holds per-client strikes and bans. It is pure: every method takes the
// time, it never reads the clock, logs or calls back.
type store struct {
	mu sync.Mutex

	maxTracked int           // clients with counters; 0 or less is no cap
	maxBans    int           // ban records; 0 or less is no cap
	maxBanTime time.Duration // doubling's cap; 0 or less is no cap

	counters map[netip.Prefix]*client
	lru      clientList // most recently struck at the front
	banRecs  map[netip.Prefix]*banRec
	byEnd    banHeap   // the same records, soonest until first
	swept    time.Time // last sweep
}

// client is one client's strikes, by jail, and its place in store.lru.
type client struct {
	prefix     netip.Prefix
	strikes    map[string]*jailStrikes
	prev, next *client // in store.lru; nil at either end
}

// clientList is a doubly-linked list of clients threaded through their own
// prev and next fields: the LRU order, written out rather than built on
// container/list, whose elements carry their value as any.
type clientList struct {
	front, back *client
}

// pushFront puts c, which is in no list, at the front.
func (l *clientList) pushFront(c *client) {
	c.prev, c.next = nil, l.front
	if l.front != nil {
		l.front.prev = c
	} else {
		l.back = c
	}
	l.front = c
}

// remove takes c, which is in l, out.
func (l *clientList) remove(c *client) {
	if c.prev != nil {
		c.prev.next = c.next
	} else {
		l.front = c.next
	}
	if c.next != nil {
		c.next.prev = c.prev
	} else {
		l.back = c.prev
	}
	c.prev, c.next = nil, nil
}

// moveToFront moves c, which is in l, to the front.
func (l *clientList) moveToFront(c *client) {
	if l.front == c {
		return
	}
	l.remove(c)
	l.pushFront(c)
}

// jailStrikes is a client's strikes in one jail, oldest first, with the jail's
// window so the sweep can trim them.
type jailStrikes struct {
	times  []time.Time
	window time.Duration
}

// banRec is a client's latest ban. until is the ban's end: the ban is live
// before it, and the record is kept until until+memory so the next ban can
// double. Ending a ban early is unban, which deletes the record, so no
// separate end is needed.
type banRec struct {
	prefix netip.Prefix
	until  time.Time
	jail   string
	count  int // bans within memory of each other's end, this one included
	index  int // position in store.byEnd
}

// banHeap is a min-heap of ban records by until, each record knowing its
// index, so a push, a removal and a fix are O(log n). It is written out rather
// than built on container/heap, whose interface traffics in any.
type banHeap []*banRec

func (h banHeap) less(i, j int) bool { return h[i].until.Before(h[j].until) }

func (h banHeap) swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h banHeap) up(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if !h.less(i, p) {
			return
		}
		h.swap(i, p)
		i = p
	}
}

// down sinks i and reports whether it moved.
func (h banHeap) down(i int) bool {
	start := i
	for {
		l := 2*i + 1
		if l >= len(h) {
			break
		}
		m := l
		if r := l + 1; r < len(h) && h.less(r, l) {
			m = r
		}
		if !h.less(m, i) {
			break
		}
		h.swap(i, m)
		i = m
	}
	return i > start
}

func (h *banHeap) push(r *banRec) {
	r.index = len(*h)
	*h = append(*h, r)
	h.up(r.index)
}

// fix restores the order after r.until changed.
func (h banHeap) fix(r *banRec) {
	if !h.down(r.index) {
		h.up(r.index)
	}
}

// remove takes r out.
func (h *banHeap) remove(r *banRec) {
	old := *h
	i, last := r.index, len(old)-1
	if i != last {
		old.swap(i, last)
	}
	old[last] = nil
	*h = old[:last]
	if i != last {
		h.fix((*h)[i])
	}
	r.index = -1
}

func newStore(maxTracked, maxBans int, maxBanTime time.Duration) *store {
	return &store{
		maxTracked: maxTracked,
		maxBans:    maxBans,
		maxBanTime: maxBanTime,
		counters:   make(map[netip.Prefix]*client),
		banRecs:    make(map[netip.Prefix]*banRec),
	}
}

// clientPrefix is the client an address belongs to: /32 for IPv4 (IPv4-mapped
// IPv6 included), /64 for IPv6. The zero Addr is no client.
func clientPrefix(a netip.Addr) (netip.Prefix, bool) {
	if !a.IsValid() {
		return netip.Prefix{}, false
	}
	a = a.Unmap().WithZone("")
	bits := 64
	if a.Is4() {
		bits = 32
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

// banned reports whether c is banned at now.
func (s *store) banned(c netip.Prefix, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	return s.live(c, now)
}

// live reports whether c has a ban that has not ended at now. s.mu is held.
func (s *store) live(c netip.Prefix, now time.Time) bool {
	r, ok := s.banRecs[c]
	return ok && now.Before(r.until)
}

// strike records a strike against c in jail. It returns the ban and true when
// this strike reaches j.MaxRetry inside j.FindTime; only that one call gets
// true. A banned client's strikes are not recorded.
func (s *store) strike(c netip.Prefix, jail string, j Jail, now time.Time) (Ban, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	if j.Off || s.live(c, now) {
		return Ban{}, false
	}
	cl, ok := s.counters[c]
	if ok {
		s.lru.moveToFront(cl)
	} else {
		if s.maxTracked > 0 {
			for len(s.counters) >= s.maxTracked && s.lru.back != nil {
				s.dropClient(s.lru.back.prefix)
			}
		}
		cl = &client{prefix: c, strikes: make(map[string]*jailStrikes)}
		s.lru.pushFront(cl)
		s.counters[c] = cl
	}
	js, ok := cl.strikes[jail]
	if !ok {
		js = &jailStrikes{}
		cl.strikes[jail] = js
	}
	js.window = time.Duration(j.FindTime)
	js.times = append(js.times, now)
	js.trim(now)
	if len(js.times) < j.MaxRetry {
		return Ban{}, false
	}
	s.dropClient(c)
	return s.put(c, jail, time.Duration(j.BanTime), now, true), true
}

// trim drops the strikes outside the window ending at now.
func (js *jailStrikes) trim(now time.Time) {
	i := 0
	for i < len(js.times) && now.Sub(js.times[i]) >= js.window {
		i++
	}
	js.times = js.times[i:]
}

// forgive clears c's strikes in jail.
func (s *store) forgive(c netip.Prefix, jail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cl, ok := s.counters[c]
	if !ok {
		return
	}
	delete(cl.strikes, jail)
	if len(cl.strikes) == 0 {
		s.dropClient(c)
	}
}

// ban bans c in jail's name. With double, the length is d doubled per recent
// previous ban and capped; without, it is d, and a live ban ending later keeps
// its end. Either way Count is recorded.
func (s *store) ban(c netip.Prefix, jail string, d time.Duration, now time.Time, double bool) Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.put(c, jail, d, now, double)
}

// unban lifts c's ban and forgets its counters and its previous bans.
func (s *store) unban(c netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.banRecs[c]; ok {
		s.dropBan(r)
	}
	s.dropClient(c)
}

// bans returns the live bans at now, soonest to end first.
func (s *store) bans(now time.Time) []Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Ban, 0, len(s.banRecs))
	for c, r := range s.banRecs {
		if now.Before(r.until) {
			out = append(out, Ban{Prefix: c, Jail: r.jail, Until: r.until, Count: r.count})
		}
	}
	slices.SortFunc(out, func(a, b Ban) int { return a.Until.Compare(b.Until) })
	return out
}

// put records a ban of c. s.mu is held.
func (s *store) put(c netip.Prefix, jail string, d time.Duration, now time.Time, double bool) Ban {
	r, ok := s.banRecs[c]
	count := 1
	if ok && !now.After(r.until.Add(memory)) {
		count = r.count + 1
	}
	if double {
		for i := 1; i < count; i++ {
			if s.maxBanTime > 0 && d >= s.maxBanTime {
				break
			}
			d *= 2
		}
		if s.maxBanTime > 0 && d > s.maxBanTime {
			d = s.maxBanTime
		}
	}
	until := now.Add(d)
	if ok && !double && until.Before(r.until) {
		// A manual ban never shortens a live one: the later end wins.
		until = r.until
	}
	if ok {
		r.until, r.jail, r.count = until, jail, count
		s.byEnd.fix(r)
	} else {
		s.evictBan()
		r = &banRec{prefix: c, until: until, jail: jail, count: count}
		s.banRecs[c] = r
		s.byEnd.push(r)
	}
	return Ban{Prefix: c, Jail: jail, Until: until, Count: count}
}

// evictBan makes room for one more record at maxBans by dropping the one that
// ends soonest, the heap's minimum. Ended records (kept for doubling) end
// before live ones, so they go first, then the live ban ending soonest.
// s.mu is held.
func (s *store) evictBan() {
	if s.maxBans <= 0 || len(s.byEnd) == 0 || len(s.banRecs) < s.maxBans {
		return
	}
	s.dropBan(s.byEnd[0])
}

// dropBan deletes r. s.mu is held.
func (s *store) dropBan(r *banRec) {
	s.byEnd.remove(r)
	delete(s.banRecs, r.prefix)
}

// dropClient forgets c's counters. s.mu is held.
func (s *store) dropClient(c netip.Prefix) {
	cl, ok := s.counters[c]
	if !ok {
		return
	}
	s.lru.remove(cl)
	delete(s.counters, c)
}

// sweep drops records past their memory and strikes past their window, at
// most once a minute of now. Callers read the clock before taking the lock, so
// a now slightly before the last sweep is normal and skips; only a jump back
// of more than a minute sweeps again. s.mu is held.
func (s *store) sweep(now time.Time) {
	if !s.swept.IsZero() {
		d := now.Sub(s.swept)
		if d < sweepEvery && d >= -sweepEvery {
			return
		}
	}
	s.swept = now
	// Records leave in until order, so the heap's minimum is the next to go.
	for len(s.byEnd) > 0 && now.After(s.byEnd[0].until.Add(memory)) {
		s.dropBan(s.byEnd[0])
	}
	for c, cl := range s.counters {
		for jail, js := range cl.strikes {
			js.trim(now)
			if len(js.times) == 0 {
				delete(cl.strikes, jail)
			}
		}
		if len(cl.strikes) == 0 {
			s.dropClient(c)
		}
	}
}
