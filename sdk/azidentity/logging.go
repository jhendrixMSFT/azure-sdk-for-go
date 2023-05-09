//go:build go1.18
// +build go1.18

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import (
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/internal/log"
)

// EventAuthentication entries contain information about authentication.
// This includes information like the names of environment variables
// used when obtaining credentials and the type of credential used.
const EventAuthentication log.Event = "Authentication"

// DefaultLogBodyFilters contains the default set of logging body filters.
// Any changes to this value *must* be made before a credential is created.
var DefaultLogBodyFilters = []func(string) string{func(s string) string {
	// redact the AAD access token from response bodies
	// WARNING: removing this filter can disclose credential information
	tokenFilter := regexp.MustCompile(`"access_token":"(\S+)"`)
	res := tokenFilter.FindStringSubmatch(s)
	if len(res) > 1 {
		// second submatch is the captured access token
		s = strings.Replace(s, res[1], "REDACTED", -1)
	}
	return s
}}

// DefaultLogBodyFilter contains the default set of logging body filters.
// Any changes to this value *must* be made before a credential is created.
var DefaultLogBodyFilter = func(s string) string {
	// redact the AAD access token from response bodies
	// WARNING: removing this filter can disclose credential information
	tokenFilter := regexp.MustCompile(`"access_token":"(\S+)"`)
	res := tokenFilter.FindStringSubmatch(s)
	if len(res) > 1 {
		// second submatch is the captured access token
		s = strings.Replace(s, res[1], "REDACTED", -1)
	}
	return s
}
