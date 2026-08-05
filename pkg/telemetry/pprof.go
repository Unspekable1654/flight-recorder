package telemetry

import (
	"net/http"
	"net/http/pprof"
)

// registerPprof mounts the standard profiling handlers.
//
// Kept in its own file so that the import of net/http/pprof - which has the
// side effect of registering handlers on http.DefaultServeMux when imported
// for its side effects elsewhere - is explicit and reviewable. Here the
// handlers are attached to a private mux only, and only when the operator
// opted in with --pprof.
func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
