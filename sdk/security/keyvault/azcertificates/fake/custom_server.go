//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

package fake

import (
	"net/http"
)

type myServerTransportInterceptor struct {
	authenticated bool
}

func (m *myServerTransportInterceptor) Intercept(req *http.Request) (*http.Response, error, bool) {
	if m.authenticated {
		return nil, nil, false
	}

	resp := &http.Response{
		Request:    req,
		Status:     "fake unauthorized",
		StatusCode: http.StatusUnauthorized,
		Body:       http.NoBody,
		Header:     http.Header{},
	}

	resp.Header.Set("WWW-Authenticate", "Bearer authorization=\"https://fake.login.microsoftonline.com/00000000-0000-0000-0000-000000000000\" resource=\"https://vault.azure.net\"")

	m.authenticated = true
	return resp, nil, true
}

func init() {
	serverTransportInterceptor = &myServerTransportInterceptor{}
}
