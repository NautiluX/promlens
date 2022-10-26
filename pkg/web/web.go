// Copyright 2022 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	toolkitweb "github.com/prometheus/exporter-toolkit/web"

	"github.com/prometheus/promlens/pkg/grafana"
	"github.com/prometheus/promlens/pkg/pageconfig"
	"github.com/prometheus/promlens/pkg/parser"
	"github.com/prometheus/promlens/pkg/react"
	"github.com/prometheus/promlens/pkg/sharer"
)

// Config configures the PromLens web UI and API.
type Config struct {
	Logger                     log.Logger
	ToolkitConfig              *toolkitweb.FlagConfig
	RoutePrefix                string
	ExternalURL                *url.URL
	Sharer                     sharer.Sharer
	GrafanaBackend             *grafana.Backend
	DefaultPrometheusURL       string
	ProxyPrometheusURL         string
	DefaultGrafanaDatasourceID int64
}

// Serve serves the PromLens web UI and API.
func Serve(cfg *Config) error {
	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "promlens_http_requests_total",
			Help: "Total count of handled HTTP requests by PromLens.",
		},
		[]string{"handler", "code"},
	)
	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "promlens_http_request_duration_seconds",
			Help:    "Histogram of latencies for HTTP requests handled by PromLens.",
			Buckets: []float64{0.005, .01, .05, .1, .2, .5, 1, 5, 10, 15, 30, 60, 120},
		},
		[]string{"handler"},
	)
	prometheus.MustRegister(requestsTotal, requestDuration)

	instr := func(handlerName string, handler http.HandlerFunc) http.HandlerFunc {
		return promhttp.InstrumentHandlerCounter(
			requestsTotal.MustCurryWith(prometheus.Labels{"handler": handlerName}),
			promhttp.InstrumentHandlerDuration(
				requestDuration.MustCurryWith(prometheus.Labels{"handler": handlerName}),
				handler,
			),
		)
	}

	if cfg.RoutePrefix != "/" {
		// If the prefix is missing for the root path, prepend it.
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, cfg.RoutePrefix, http.StatusFound)
		})
	}

	// TODO: Clean this up.
	if cfg.RoutePrefix == "/" {
		cfg.RoutePrefix = ""
	}

	http.HandleFunc(cfg.RoutePrefix+"/api/page_config", instr("/api/page_config", pageconfig.Handle(cfg.Sharer, cfg.GrafanaBackend, cfg.DefaultPrometheusURL, cfg.ProxyPrometheusURL, cfg.DefaultGrafanaDatasourceID)))
	http.HandleFunc(cfg.RoutePrefix+"/api/link", instr("/api/link", sharer.Handle(cfg.Logger, cfg.Sharer)))
	http.HandleFunc(cfg.RoutePrefix+"/api/parse", instr("/api/parse", parser.Handle))
	if cfg.GrafanaBackend != nil {
		http.HandleFunc(cfg.RoutePrefix+"/api/grafana/", instr("/api/grafana", cfg.GrafanaBackend.Handle(cfg.RoutePrefix)))
	}
	if cfg.ProxyPrometheusURL != "" {
		p := proxy{url: cfg.ProxyPrometheusURL}
		http.HandleFunc(cfg.RoutePrefix+"/api/proxy/", instr("/api/proxy", p.HandleProxy))
	}
	http.HandleFunc(cfg.RoutePrefix+"/metrics", instr("/metrics", promhttp.Handler().ServeHTTP))
	http.HandleFunc(cfg.RoutePrefix+"/", instr("static", react.Handle(cfg.RoutePrefix, cfg.ExternalURL)))

	server := &http.Server{}
	return toolkitweb.ListenAndServe(server, cfg.ToolkitConfig, cfg.Logger)
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func appendHostToXForwardHeader(header http.Header, host string) {
	// If we aren't the first proxy retain prior
	// X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

type proxy struct {
	url string
}

func (p *proxy) HandleProxy(wr http.ResponseWriter, req *http.Request) {
	fmt.Println(req.RemoteAddr, " ", req.Method, " ", req.URL)

	path := req.URL.Path[10:len(req.URL.Path)]
	fmt.Println(path)
	newUrl, _ := url.Parse(p.url)
	newUrl.Path = newUrl.Path + path
	newUrl.RawQuery = req.URL.Query().Encode()
	newUrl.Fragment = req.URL.Fragment
	fmt.Println(newUrl.String())
	req2, err := http.NewRequest(req.Method, newUrl.String(), req.Body)
	if err != nil {
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		panic(err)
	}
	copyHeader(req2.Header, req.Header)
	delHopHeaders(req2.Header)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		appendHostToXForwardHeader(req2.Header, clientIP)
	}
	b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		fmt.Print(err)
	}

	token := string(b)
	fmt.Println(token)
	req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req2)
	if err != nil {
		http.Error(wr, "Server Error", http.StatusInternalServerError)
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println(req2.RemoteAddr, " ", resp.Status)

	delHopHeaders(resp.Header)

	copyHeader(wr.Header(), resp.Header)
	wr.WriteHeader(resp.StatusCode)
	io.Copy(wr, resp.Body)
}
