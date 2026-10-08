package region

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"citadel/internal/api"
)

// Router sends a request signed for another region of this cloud to that
// region. In AWS each region has its own endpoint, and a request signed for
// one region is refused by another. Clients that manage several regions
// through one endpoint (the Terraform provider reaches a global table's
// replicas through the endpoint of the provider that owns the table, signing
// for the replica's region) would otherwise talk to the wrong region. The
// request goes on unchanged, Host header included, so its signature still
// verifies there. Requests signed for a region outside the registry (for
// example us-east-1) are served locally.
type Router struct {
	next    http.Handler
	proxies map[string]*httputil.ReverseProxy
}

// hdrRouted marks a routed request so it is never routed twice.
const hdrRouted = "X-Citadel-Routed-From"

// NewRouter wraps next, the region's own front door.
func NewRouter(reg *Registry, self string, next http.Handler, logger *slog.Logger) *Router {
	rt := &Router{next: next, proxies: map[string]*httputil.ReverseProxy{}}
	for _, g := range reg.Regions {
		if g.Name == self {
			continue
		}
		target, err := url.Parse(g.Endpoint)
		if err != nil {
			continue
		}
		name := g.Name
		rt.proxies[name] = &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(target)
				pr.Out.Host = pr.In.Host // part of the signature
				pr.Out.Header.Set(hdrRouted, self)
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				logger.Warn("route request to its region", "dest", name, "err", err)
				api.WriteError(w, r, api.DetectService(r), http.StatusServiceUnavailable, "ServiceUnavailable",
					"Region "+name+" is unreachable. Retry when it returns.")
			},
		}
	}
	return rt
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/_citadel/") && r.Header.Get(hdrRouted) == "" {
		if p, ok := rt.proxies[SignedRegion(r)]; ok {
			p.ServeHTTP(w, r)
			return
		}
	}
	rt.next.ServeHTTP(w, r)
}

// SignedRegion returns the region in a SigV4 request's credential scope
// (AKID/date/region/service/aws4_request), from the Authorization header or
// a presigned URL, or "" when there is none.
func SignedRegion(r *http.Request) string {
	cred := r.URL.Query().Get("X-Amz-Credential")
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "AWS4-") {
		if _, rest, ok := strings.Cut(a, "Credential="); ok {
			cred, _, _ = strings.Cut(rest, ",")
		}
	}
	parts := strings.Split(strings.TrimSpace(cred), "/")
	if len(parts) != 5 {
		return ""
	}
	return parts[2]
}
