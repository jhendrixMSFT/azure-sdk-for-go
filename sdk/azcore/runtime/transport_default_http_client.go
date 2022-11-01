//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

var defaultHTTPClient *http.Client

func init() {
	clientCache = make(map[clientConfig]*http.Client)
	cfg := defaultClientConfig()
	defaultHTTPClient = createClient(cfg)
}

var clientCache map[clientConfig]*http.Client

type clientConfig struct {
	ForceHTTP2    bool
	Renegotiation tls.RenegotiationSupport
}

func defaultClientConfig() clientConfig {
	return clientConfig{ForceHTTP2: true, Renegotiation: tls.RenegotiateNever}
}

func getOrCreateClient(cfg clientConfig) *http.Client {
	if client, ok := clientCache[cfg]; ok {
		return client
	}
	return createClient(cfg)
}

func createClient(cfg clientConfig) *http.Client {
	defaultTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     cfg.ForceHTTP2,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:    tls.VersionTLS12,
			Renegotiation: cfg.Renegotiation,
		},
	}
	return &http.Client{Transport: defaultTransport}
}

func addToCache(cfg clientConfig, client *http.Client) {
	clientCache[cfg] = client
}

type defaultTransportPolicy struct {
	client *http.Client
	valid  bool
}

func newDefaultTransportPolicy() *defaultTransportPolicy {
	return &defaultTransportPolicy{client: defaultHTTPClient}
}

func (d *defaultTransportPolicy) Do(req *http.Request) (*http.Response, error) {
	if d.valid {
		return d.client.Do(req)
	}

	// initialize with default, preferred values
	cfg := defaultClientConfig()

	for {
		resp, err := d.client.Do(req)
		if resp != nil {
			d.valid = true
			addToCache(cfg, d.client)
			return resp, err
		}

		if errStr := err.Error(); strings.Contains(errStr, "HTTP_1_1_REQUIRED") {
			// peer doesn't support HTTP/2
			cfg.ForceHTTP2 = false
			d.client = getOrCreateClient(cfg)
		} else if strings.Contains(errStr, "tls: no renegotiation") {
			// peer requires TLS renegotiation
			cfg.Renegotiation = tls.RenegotiateFreelyAsClient
			d.client = getOrCreateClient(cfg)
		} else {
			return resp, err
		}
	}
}
