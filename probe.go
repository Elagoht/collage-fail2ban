package fail2ban

import (
	"net/http"
	"strings"
)

// builtinProbes are the path prefixes no real reader asks for, lower-cased.
var builtinProbes = []string{
	"/.env",
	"/.git/",
	"/.aws/",
	"/wp-login.php",
	"/wp-admin",
	"/xmlrpc.php",
	"/phpmyadmin",
	"/cgi-bin/",
	"/vendor/phpunit",
}

// probePrefixes is the built-in list with extra added, lower-cased. An empty
// entry is skipped: as a prefix it would make every path a probe.
func probePrefixes(extra []string) []string {
	out := make([]string, 0, len(builtinProbes)+len(extra))
	out = append(out, builtinProbes...)
	for _, e := range extra {
		if e != "" {
			out = append(out, strings.ToLower(e))
		}
	}
	return out
}

// isProbe reports whether r's path starts, case-insensitively, with one of
// prefixes. It is a plain prefix match: "/.env" also matches "/.envoy".
func isProbe(r *http.Request, prefixes []string) bool {
	p := strings.ToLower(r.URL.Path)
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// isEarlyRejection reports whether collage answers r before routing because of
// something only a scanner sends: an encoded slash, or a "." or ".." segment.
// A doubled slash is redirected by collage too, but a real reader follows a
// sloppy link like "/blog//post", so it is not counted.
func isEarlyRejection(r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.URL.EscapedPath()), "%2f") {
		return true
	}
	for seg := range strings.SplitSeq(r.URL.Path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}
