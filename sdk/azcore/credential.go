// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azcore

import (
	"context"
	"encoding/json"
	"time"
)

// TokenCredential represents a credential capable of providing an OAuth token.
type TokenCredential interface {
	// GetToken requests an access token for the specified set of scopes.
	GetToken(ctx context.Context, scopes []string) (*AccessToken, error)
}

// AccessToken represents an Azure service bearer access token with expiry information.
type AccessToken struct {
	Token     string      `json:"access_token"`
	ExpiresIn json.Number `json:"expires_in"`
	ExpiresOn time.Time
}
