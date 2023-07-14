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
	"sync"
	"time"
)

var defaultHTTPClient *http.Client

func init() {
	defaultHTTPClient = newClient(defaultClientConfig())
}

func newClient(cfg clientConfig) *http.Client {
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
	return &http.Client{
		Transport: defaultTransport,
	}
}

type defaultTransport struct {
	client *http.Client
	rwMu   *sync.RWMutex
}

func newDefaultTransport() *defaultTransport {
	return &defaultTransport{
		rwMu: &sync.RWMutex{},
	}
}

func (d *defaultTransport) Do(req *http.Request) (*http.Response, error) {
	if client := d.getClient(); client != nil {
		return client.Do(req)
	}

	d.rwMu.Lock()
	defer d.rwMu.Unlock()

	// TODO: we're holding the lock while performing I/O

	if d.client != nil {
		// another goroutine beat us to it
		return d.client.Do(req)
	}

	// start with the default client
	d.client = defaultHTTPClient

	// initialize with default, preferred values
	cfg := defaultClientConfig()

	for {
		resp, err := d.client.Do(req)
		if resp != nil {
			return resp, err
		}

		if errStr := err.Error(); strings.Contains(errStr, "HTTP_1_1_REQUIRED") {
			// peer doesn't support HTTP/2
			cfg.ForceHTTP2 = false
			d.client = newClient(cfg)
		} else if strings.Contains(errStr, "tls: no renegotiation") {
			// peer requires TLS renegotiation
			cfg.Renegotiation = tls.RenegotiateFreelyAsClient
			d.client = newClient(cfg)
		} else {
			return resp, err
		}
	}
}

func (d *defaultTransport) getClient() *http.Client {
	d.rwMu.RLock()
	defer d.rwMu.RUnlock()
	return d.client
}

type clientConfig struct {
	ForceHTTP2    bool
	Renegotiation tls.RenegotiationSupport
}

func defaultClientConfig() clientConfig {
	return clientConfig{ForceHTTP2: true, Renegotiation: tls.RenegotiateNever}
}
