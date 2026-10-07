// A collage plugin that bans clients that probe or brute-force a site, with the
// standard library alone.
//
// It requires collage the way any consumer does.
module github.com/Elagoht/collage-fail2ban

go 1.26

require github.com/Elagoht/collage v0.52.0

retract v0.1.2 // tagged by mistake on the previous release's code; use v0.1.3 or later
