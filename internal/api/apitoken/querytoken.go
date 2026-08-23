// Package apitoken handles the `?token=` API credential that browsers are
// forced to use for transports which cannot carry an Authorization header.
//
// A browser cannot set request headers on a WebSocket handshake (`new WebSocket`)
// or on an EventSource/SSE subscription, so both dashboards fall back to putting
// the API token in the query string, which the API's auth middleware accepts.
// That works, but a credential in a URL is a credential in every log: chi's
// request logger formats r.RequestURI verbatim, so every WebSocket upgrade and
// every log-stream subscription wrote the operator's api.token into the
// process's own stdout log at info level.
//
// StripQueryMiddleware closes that off by lifting the token out of the URL into
// the request context before any other middleware observes the request. The
// credential keeps working, but nothing downstream — logger included — can see
// it in the URL any more.
//
// This cannot help with logging that happens BEFORE Bifrost: the token is still
// in the request line on the wire, so a reverse proxy in front of Bifrost will
// still record it. From a browser, prefer the session-cookie flow
// (POST /api/v1/login), which keeps the credential out of every URL.
package apitoken

import (
	"context"
	"net/http"
)

// QueryParam is the query-string parameter carrying the API token.
const QueryParam = "token"

// RedactedValue replaces the token in the URL seen by downstream middleware. A
// placeholder is used rather than dropping the parameter so that logs still show
// a credential was presented — useful when debugging a 401 — without disclosing
// what it was.
const RedactedValue = "REDACTED"

type contextKey struct{}

// queryTokenKey identifies the stripped token in a request context.
var queryTokenKey = contextKey{}

// StripQueryMiddleware removes the `?token=` parameter from the request URL and
// stashes its value in the request context, where the auth middleware reads it
// via FromContext.
//
// It must be installed as the FIRST middleware in the chain, ahead of the
// request logger, or the unredacted URL will already have been logged.
func StripQueryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		token := query.Get(QueryParam)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Rewrite the URL in place of the original so neither the logger nor any
		// handler can observe the credential. RequestURI is what chi's logger
		// prints, so it has to be rebuilt too.
		query.Set(QueryParam, RedactedValue)
		redacted := *r.URL
		redacted.RawQuery = query.Encode()

		scrubbed := r.Clone(context.WithValue(r.Context(), queryTokenKey, token))
		scrubbed.URL = &redacted
		scrubbed.RequestURI = redacted.RequestURI()

		next.ServeHTTP(w, scrubbed)
	})
}

// FromContext returns the API token that StripQueryMiddleware lifted out of the
// query string, or "" when none was presented.
func FromContext(r *http.Request) string {
	token, ok := r.Context().Value(queryTokenKey).(string)
	if !ok {
		return ""
	}
	return token
}
