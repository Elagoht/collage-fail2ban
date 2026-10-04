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
// prefixes — a plain prefix match: "/.env" also matches "/.envoy" — or has,
// anywhere, a segment starting with ".env" or a segment ".git": scanners look
// for the files a deploy forgot under every directory, "/api/.env",
// "/backend/.git/config", and "/.git" itself.
func isProbe(r *http.Request, prefixes []string) bool {
	p := strings.ToLower(r.URL.Path)
	for _, pre := range prefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == ".git" || strings.HasPrefix(seg, ".env") {
			return true
		}
	}
	return false
}

// isSubresource reports whether r is a browser request another page could
// have made its reader send: one from another site (Sec-Fetch-Site:
// cross-site: a no-cors fetch, a hidden iframe, a link), or a part of a page —
// an image, a script, a style sheet — by its Sec-Fetch-Dest: anything but a
// document, a frame or a fetch ("empty"). A page anywhere can make its readers'
// browsers ask for any path, so these requests never strike.
func isSubresource(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return true
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "", "document", "iframe", "empty":
		return false
	}
	return true
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
