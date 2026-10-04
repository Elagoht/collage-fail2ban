package fail2ban

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

// Duration is a time.Duration that reads from configuration as Go writes one,
// "10m", as well as a number of nanoseconds.
type Duration time.Duration

// UnmarshalJSON reads "10m" or a number of nanoseconds.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("fail2ban: %w", err)
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("fail2ban: a duration is a string like \"10m\" or a number of nanoseconds")
	}
	*d = Duration(n)
	return nil
}

// Options configures the plugin.
type Options struct {
	Jails         map[string]Jail `json:"jails"`         // overrides and app jails, by name
	ProbePaths    []string        `json:"probePaths"`    // added to the built-in list
	Allow         []string        `json:"allow"`         // addresses and CIDR ranges never counted or banned
	MaxBanTime    Duration        `json:"maxBanTime"`    // cap for repeat offenders, default "24h"
	MaxTracked    int             `json:"maxTracked"`    // clients with live counters, default 10000
	MaxBans       int             `json:"maxBans"`       // live bans, default 10000
	InDevelopment bool            `json:"inDevelopment"` // default false: nothing happens in development

	OnBan func(b Ban) `json:"-"`
}

// Jail is the settings of one jail.
type Jail struct {
	MaxRetry int      `json:"maxRetry"` // strikes that ban
	FindTime Duration `json:"findTime"` // window strikes are counted in
	BanTime  Duration `json:"banTime"`  // first ban's length
	Off      bool     `json:"off"`      // the jail counts nothing
}

// Ban is a client banned by a jail.
type Ban struct {
	Prefix netip.Prefix // the client: /32 for IPv4, /64 for IPv6
	Jail   string
	Until  time.Time
	Count  int // bans of this client in the last 24 hours, this one included
}

const (
	defaultMaxBanTime = 24 * time.Hour
	defaultMaxTracked = 10000
	defaultMaxBans    = 10000
)

// defaultJail is what a jail without built-in settings starts from.
var defaultJail = Jail{MaxRetry: 5, FindTime: Duration(10 * time.Minute), BanTime: Duration(15 * time.Minute)}

// builtinJails are the jails the plugin ships.
var builtinJails = map[string]Jail{
	"probe":    {MaxRetry: 3, FindTime: Duration(10 * time.Minute), BanTime: Duration(time.Hour)},
	"notfound": {MaxRetry: 50, FindTime: Duration(time.Minute), BanTime: Duration(10 * time.Minute)},
}

// jail resolves name to its effective settings: the built-in defaults (or 5 /
// 10m / 15m), each non-zero field of o.Jails[name] overriding, and Off copied.
func (o Options) jail(name string) Jail {
	j, ok := builtinJails[name]
	if !ok {
		j = defaultJail
	}
	if c, ok := o.Jails[name]; ok {
		if c.MaxRetry != 0 {
			j.MaxRetry = c.MaxRetry
		}
		if c.FindTime != 0 {
			j.FindTime = c.FindTime
		}
		if c.BanTime != 0 {
			j.BanTime = c.BanTime
		}
		j.Off = c.Off
	}
	return j
}

// validate checks the numbers, jails in name order so the error is stable.
func (o *Options) validate() error {
	names := make([]string, 0, len(o.Jails))
	for n := range o.Jails {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		j := o.Jails[n]
		switch {
		case j.MaxRetry < 0:
			return fmt.Errorf("fail2ban: jail %q: maxRetry %d must not be negative", n, j.MaxRetry)
		case j.FindTime < 0:
			return fmt.Errorf("fail2ban: jail %q: findTime must not be negative", n)
		case j.BanTime < 0:
			return fmt.Errorf("fail2ban: jail %q: banTime must not be negative", n)
		}
	}
	switch {
	case o.MaxBanTime < 0:
		return errors.New("fail2ban: maxBanTime must not be negative")
	case o.MaxTracked < 0:
		return fmt.Errorf("fail2ban: maxTracked %d must not be negative", o.MaxTracked)
	case o.MaxBans < 0:
		return fmt.Errorf("fail2ban: maxBans %d must not be negative", o.MaxBans)
	}
	return nil
}

// parseAllow parses addresses and CIDR ranges; a bare address is a /32 or
// /128. Prefixes come back masked, and IPv4-mapped IPv6 as IPv4.
func parseAllow(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		pfx, err := netip.ParsePrefix(e)
		if err != nil {
			addr, aerr := netip.ParseAddr(e)
			if aerr != nil {
				return nil, fmt.Errorf("fail2ban: allow entry %q is not an address or a CIDR range", e)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		if pfx.Addr().Is4In6() {
			// ::ffff:a.b.c.d/n is the IPv4 range a.b.c.d/(n-96).
			bits := pfx.Bits() - 96
			if bits < 0 {
				return nil, fmt.Errorf("fail2ban: allow entry %q is wider than the IPv4 range it maps", e)
			}
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), bits)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}
