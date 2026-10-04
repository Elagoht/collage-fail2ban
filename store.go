package fail2ban

import (
	"container/list"
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
	lru      *list.List // of netip.Prefix, most recently struck at the front
	banRecs  map[netip.Prefix]*banRec
	swept    time.Time // last sweep
}

// client is one client's strikes, by jail.
type client struct {
	strikes map[string]*jailStrikes
	elem    *list.Element // in store.lru
}

// jailStrikes is a client's strikes in one jail, oldest first, with the jail's
// window so the sweep can trim them.
type jailStrikes struct {
	times  []time.Time
	window time.Duration
}

// banRec is a client's latest ban. It is live until until and kept until
// until+memory so the next ban can double; until is the ban's end (lastEnd).
type banRec struct {
	until time.Time
	jail  string
	count int // bans within memory of each other's end, this one included
}

func newStore(maxTracked, maxBans int, maxBanTime time.Duration) *store {
	return &store{
		maxTracked: maxTracked,
		maxBans:    maxBans,
		maxBanTime: maxBanTime,
		counters:   make(map[netip.Prefix]*client),
		lru:        list.New(),
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
		s.lru.MoveToFront(cl.elem)
	} else {
		if s.maxTracked > 0 {
			for len(s.counters) >= s.maxTracked {
				back := s.lru.Back()
				if back == nil {
					break
				}
				s.dropClient(back.Value.(netip.Prefix))
			}
		}
		cl = &client{strikes: make(map[string]*jailStrikes)}
		cl.elem = s.lru.PushFront(c)
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
// previous ban and capped; without, it is d. Either way Count is recorded.
func (s *store) ban(c netip.Prefix, jail string, d time.Duration, now time.Time, double bool) Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.put(c, jail, d, now, double)
}

// unban lifts c's ban and forgets its counters and its previous bans.
func (s *store) unban(c netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.banRecs, c)
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
	if !ok {
		s.evictBan()
		r = &banRec{}
		s.banRecs[c] = r
	}
	*r = banRec{until: now.Add(d), jail: jail, count: count}
	return Ban{Prefix: c, Jail: jail, Until: r.until, Count: count}
}

// evictBan makes room for one more record at maxBans by dropping the one that
// ends soonest. Ended records (kept for doubling) end before live ones, so they
// go first, then the live ban ending soonest. A linear scan: at the default
// 10,000 records it runs only when the cap is full. s.mu is held.
func (s *store) evictBan() {
	if s.maxBans <= 0 || len(s.banRecs) < s.maxBans {
		return
	}
	var victim netip.Prefix
	var soonest time.Time
	first := true
	for c, r := range s.banRecs {
		if first || r.until.Before(soonest) {
			victim, soonest, first = c, r.until, false
		}
	}
	if !first {
		delete(s.banRecs, victim)
	}
}

// dropClient forgets c's counters. s.mu is held.
func (s *store) dropClient(c netip.Prefix) {
	cl, ok := s.counters[c]
	if !ok {
		return
	}
	s.lru.Remove(cl.elem)
	delete(s.counters, c)
}

// sweep drops records past their memory and strikes past their window, at
// most once a minute of now. A now before the last sweep sweeps again. s.mu is
// held.
func (s *store) sweep(now time.Time) {
	if d := now.Sub(s.swept); !s.swept.IsZero() && d >= 0 && d < sweepEvery {
		return
	}
	s.swept = now
	for c, r := range s.banRecs {
		if now.After(r.until.Add(memory)) {
			delete(s.banRecs, c)
		}
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
