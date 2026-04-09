// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModsecurity_ServeHTTP(t *testing.T) {

	req, err := http.NewRequest(http.MethodGet, "http://proxy.com/test", bytes.NewBuffer([]byte("Request")))

	if err != nil {
		log.Fatal(err)
	}

	type response struct {
		Body       string
		StatusCode int
	}

	serviceResponse := response{
		StatusCode: 200,
		Body:       "Response from service",
	}

	tests := []struct {
		name            string
		request         http.Request
		wafResponse     response
		serviceResponse response
		expectBody      string
		expectStatus    int
	}{
		{
			name:    "Forward request when WAF found no threats",
			request: *req,
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    200,
		},
		{
			name:    "Intercepts request when WAF found threats",
			request: *req,
			wafResponse: response{
				StatusCode: 403,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from waf",
			expectStatus:    403,
		},
		{
			name: "Does not forward Websockets",
			request: http.Request{
				Body: http.NoBody,
				Header: http.Header{
					"Upgrade": []string{"Websocket"},
				},
			},
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    200,
		},
		{
			name: "Accept payloads smaller than limits",
			request: http.Request{
				Body: generateLargeBody(1024),
			},
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "Response from service",
			expectStatus:    http.StatusOK,
		},
		{
			name: "Reject too big payloads",
			request: http.Request{
				Body: generateLargeBody(1025),
			},
			wafResponse: response{
				StatusCode: 200,
				Body:       "Response from waf",
			},
			serviceResponse: serviceResponse,
			expectBody:      "\n",
			expectStatus:    http.StatusRequestEntityTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			modsecurityMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(bytes.NewReader([]byte(tt.wafResponse.Body))),
					StatusCode: tt.wafResponse.StatusCode,
					Header:     http.Header{},
				}
				forwardResponse(&resp, w)
			}))

			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := http.Response{
					Body:       io.NopCloser(bytes.NewReader([]byte(tt.serviceResponse.Body))),
					StatusCode: tt.serviceResponse.StatusCode,
					Header:     http.Header{},
				}
				forwardResponse(&resp, w)
			})

			middleware := &Modsecurity{
				next:           httpServiceHandler,
				modSecurityUrl: modsecurityMockServer.URL,
				maxBodySize:    1024,
				name:           "modsecurity-middleware",
				httpClient:     http.DefaultClient,
				logger:         log.New(io.Discard, "", log.LstdFlags),
			}

			rw := httptest.NewRecorder()

			middleware.ServeHTTP(rw, &tt.request)

			resp := rw.Result()
			body, _ := io.ReadAll(resp.Body)

			assert.Equal(t, tt.expectBody, string(body))
			assert.Equal(t, tt.expectStatus, resp.StatusCode)
		})
	}
}

func generateLargeBody(size int) io.ReadCloser {
	var str = make([]byte, size)
	return io.NopCloser(bytes.NewReader(str))
}

func TestModsecurity_BypassRules(t *testing.T) {
	serviceResponse := "Response from service"

	tests := []struct {
		name        string
		bypassRules []compiledBypassRule
		method      string
		path        string
		expectWAF   bool // whether the WAF mock server should be called
	}{
		{
			name: "Bypasses WAF when method and path match",
			bypassRules: []compiledBypassRule{
				{method: http.MethodGet, pathRegexp: regexp.MustCompile(`/search/v1/statement/executing/`)},
			},
			method:    http.MethodGet,
			path:      "/search/v1/statement/executing/abc123",
			expectWAF: false,
		},
		{
			name: "Does not bypass WAF when method does not match",
			bypassRules: []compiledBypassRule{
				{method: http.MethodGet, pathRegexp: regexp.MustCompile(`/search/v1/statement/executing/`)},
			},
			method:    http.MethodPost,
			path:      "/search/v1/statement/executing/abc123",
			expectWAF: true,
		},
		{
			name: "Does not bypass WAF when path does not match",
			bypassRules: []compiledBypassRule{
				{method: http.MethodGet, pathRegexp: regexp.MustCompile(`/search/v1/statement/executing/`)},
			},
			method:    http.MethodGet,
			path:      "/search/v1/statement/queued/abc123",
			expectWAF: true,
		},
		{
			name: "Bypasses WAF with method-only rule",
			bypassRules: []compiledBypassRule{
				{method: http.MethodGet},
			},
			method:    http.MethodGet,
			path:      "/any/path",
			expectWAF: false,
		},
		{
			name: "Bypasses WAF with path-only rule",
			bypassRules: []compiledBypassRule{
				{pathRegexp: regexp.MustCompile(`/health`)},
			},
			method:    http.MethodPost,
			path:      "/health",
			expectWAF: false,
		},
		{
			name:      "No bypass rules — WAF always runs",
			method:    http.MethodGet,
			path:      "/search/v1/statement/executing/abc123",
			expectWAF: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wafCalled := false
			modsecurityMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wafCalled = true
				w.WriteHeader(http.StatusOK)
			}))
			defer modsecurityMockServer.Close()

			httpServiceHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(serviceResponse))
			})

			middleware := &Modsecurity{
				next:           httpServiceHandler,
				modSecurityUrl: modsecurityMockServer.URL,
				maxBodySize:    1024 * 1024,
				name:           "modsecurity-middleware",
				httpClient:     http.DefaultClient,
				logger:         log.New(io.Discard, "", log.LstdFlags),
				bypassRules:    tt.bypassRules,
			}

			req, _ := http.NewRequest(tt.method, "http://proxy.com"+tt.path, http.NoBody)
			rw := httptest.NewRecorder()
			middleware.ServeHTTP(rw, req)

			assert.Equal(t, http.StatusOK, rw.Result().StatusCode)
			assert.Equal(t, tt.expectWAF, wafCalled, "WAF called mismatch")
		})
	}
}
