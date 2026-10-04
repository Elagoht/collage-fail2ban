# elagoht/fail2ban

A collage plugin that bans clients that probe or brute-force a site, with the
standard library alone. It counts strikes per client in named jails, and a client
that reaches a jail's limit gets a plain `403` for the length of the ban.

```sh
go get github.com/Elagoht/collage-fail2ban
```

```json
{
  "elagoht/fail2ban": {
    "jails": {
      "probe": { "banTime": "6h" },
      "notfound": { "off": true }
    },
    "allow": ["203.0.113.7", "10.0.0.0/8"]
  }
}
```

```go
f2b := fail2ban.New(fail2ban.Options{
	OnBan: func(b fail2ban.Ban) { notifyAdmin(b.Prefix, b.Jail, b.Until) },
})

app, err := collage.New(&collage.Config{
	Plugins: []collage.Plugin{f2b /* , the rest */},
})
```

Requires collage v0.47.0 or later, for `Server.TrustedProxies`, `collage.ClientIP`,
and a `RequestHook` that sees the requests collage rejects before routing.

**List it first in `Config.Plugins`**, so its ban check runs before the other
plugins' middleware.

## Behind a proxy: set `Server.TrustedProxies`

The plugin bans the client address `collage.ClientIP` reports. Behind a reverse
proxy or a CDN that is the proxy's own address unless you tell collage which
proxies to trust with `Server.TrustedProxies`. Without it, **the proxy is the
client: one scanner gets your proxy banned, and with it every visitor.** Set
`TrustedProxies` before you deploy this plugin behind anything.

A client is an IPv4 address, or an IPv6 `/64`: a host that owns a `/64` can pick any
address in it, so the whole range is one client.

## Jails

A jail counts strikes. A client with `maxRetry` strikes within `findTime` is banned
for `banTime`.

| Jail | `maxRetry` | `findTime` | `banTime` | Strikes on |
| --- | --- | --- | --- | --- |
| `probe` | 3 | `10m` | `1h` | a request for a probe path, or one collage rejects early (see below) |
| `notfound` | 50 | `1m` | `10m` | any other request answered `404` |
| any other name | 5 | `10m` | `15m` | only your own `Report` calls |

Override a jail by name. A field left out or zero keeps the default, and `"off": true`
turns the jail off:

```json
{
  "elagoht/fail2ban": {
    "jails": {
      "probe": { "banTime": "6h" },
      "notfound": { "off": true },
      "login": { "maxRetry": 3 }
    }
  }
}
```

A duration is a Go duration string (`"10m"`) or a number of nanoseconds.

### Probe detection

A request is a probe when its path starts, case-insensitively, with one of the
built-in prefixes:

`/.env`, `/.git/`, `/.aws/`, `/wp-login.php`, `/wp-admin`, `/xmlrpc.php`,
`/phpmyadmin`, `/cgi-bin/`, `/vendor/phpunit`

It is a plain prefix match, so `/.env` also matches `/.envoy`. Add your own with
`probePaths`; every entry must start with `/`.

A request with an encoded slash (`%2f`) or a `.` or `..` segment in its path counts
as a probe too: collage rejects those before routing, and only a scanner sends them.
A doubled slash alone (`/blog//post`) does not count; a real reader follows a
sloppy link.

## Repeat bans

The n-th ban of a client within 24 hours of the previous ban's end lasts the jail's
`banTime` x 2^(n-1), capped at `maxBanTime` (default `24h`). A ban after a longer
quiet spell starts over.

A manual ban (`Ban`) is not doubled, and replaces any ban the client already has.
`Unban` lifts the ban and also forgets the client's earlier bans.

## What a banned client sees

A plain `403 Forbidden` with the body `Forbidden`, `Content-Type: text/plain` and
`Cache-Control: no-store`. It is never the site's error page, by design: rendering
a page for a banned client would make a flood of banned requests expensive.

A banned client's request with an encoded slash or a dirty path (`.` / `..`) still
gets collage's own `404` or redirect, because collage answers those before any
middleware runs. Those requests are not counted again.

## Failed logins: `Report` and `Forgive`

Keep the plugin you register and call it from your handlers. `Report` strikes the
request's client in a jail, `Forgive` clears its strikes there:

```go
func login(f2b *fail2ban.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticate(r)
		if !ok {
			f2b.Report(r, "login") // 5 failures in 10m: banned for 15m
			http.Error(w, "wrong email or password", http.StatusUnauthorized)
			return
		}
		f2b.Forgive(r, "login")
		startSession(w, r, user)
	}
}
```

A jail name the plugin does not know uses 5 strikes / `10m` / `15m`; configure it
under `jails` like any other.

## Allow

`allow` lists addresses and CIDR ranges (`"203.0.113.7"`, `"10.0.0.0/8"`). A client
in it is never counted and never banned, not even by `Ban`, and is never answered
`403`, even when it sits inside a banned IPv6 `/64`. Allow your office, your monitor
and your own load balancer.

## Manual API and `OnBan`

| Call | Does |
| --- | --- |
| `Ban(addr netip.Addr, d time.Duration)` | Bans the client in jail `manual` for `d`, without doubling; replaces an existing ban |
| `Unban(addr netip.Addr)` | Lifts the ban, and forgets the client's strikes and earlier bans |
| `Bans() []Ban` | The live bans, soonest to end first |
| `Report(r, jail)` / `Forgive(r, jail)` | See above |

A `Ban` carries `Prefix` (`/32` for IPv4, `/64` for IPv6), `Jail`, `Until` and
`Count` (bans of this client in the last 24 hours, this one included).

`Options.OnBan` is called after each new ban, on the request's goroutine: keep it
fast, and hand slow work to a goroutine of your own. A panic in it is recovered and
logged, and the ban stands. Each ban is logged at `Warn`:
message `fail2ban: banned` with attributes `client`, `jail` and `until`. `OnBan` is Go only.

## Options

| Option | JSON | Default | |
| --- | --- | --- | --- |
| `Jails` | `jails` | the built-in jails | Overrides by jail name, and jails of your own |
| `ProbePaths` | `probePaths` | | Prefixes added to the built-in list; each starts with `/` |
| `Allow` | `allow` | | Addresses and CIDR ranges never counted or banned |
| `MaxBanTime` | `maxBanTime` | `"24h"` | Cap for repeat bans |
| `MaxTracked` | `maxTracked` | `10000` | Clients with live strike counters |
| `MaxBans` | `maxBans` | `10000` | Bans kept |
| `InDevelopment` | `inDevelopment` | `false` | Without it nothing happens in dev mode |
| `OnBan` | not configurable | | `func(b Ban)`. Go only |

A jail takes `maxRetry`, `findTime`, `banTime` and `off`. A negative number
fails startup.

## Development

In dev mode nothing happens unless `inDevelopment` is set: no counting, no bans,
and `Report`, `Forgive`, `Ban`, `Unban` and `Bans` do nothing. Calls before the app
has started do nothing either.

## Limits

- Per process and in memory. Instances do not share bans, and a restart clears
  them.
- Bounded by `maxTracked` and `maxBans`. At the `maxBans` cap the ban ending
  soonest is evicted, so an attacker with thousands of addresses can push older
  bans out.
- No per-account protection: a password guessed from many addresses strikes none of
  them often enough. Lock the account in your own code for that.
- Not a replacement for rate limiting; see `elagoht/ratelimit`. It reacts after
  strikes, it does not smooth load.
- The `403` is plain by design, and a banned client still gets collage's own answer
  to encoded-slash and dirty-path requests.
