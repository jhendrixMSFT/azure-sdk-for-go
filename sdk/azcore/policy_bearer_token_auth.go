// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azcore

import (
	"context"
	"sync"
	"time"
)

// NewBearerTokenPolicy returns a Policy for applying bearer token authorization to a request.
func NewBearerTokenPolicy(creds TokenCredential, scopes []string) Policy {
	// set the token as expired so first call to Do() refreshes it
	return &bearerTokenPolicy{creds: creds, scopes: scopes, expiresOn: time.Now().UTC()}
}

type bearerTokenPolicy struct {
	// take lock when manipulating header/expiresOn fields
	lock      sync.RWMutex
	header    string
	expiresOn time.Time
	creds     TokenCredential // R/O
	scopes    []string        // R/O
}

// Do implements the Policy interface on bearerTokenPolicy.
func (b *bearerTokenPolicy) Do(ctx context.Context, req *Request) (*Response, error) {
	var bt string
	// take read lock and check if the token has expired
	b.lock.RLock()
	now := time.Now().UTC()
	if now.Equal(b.expiresOn) || now.After(b.expiresOn) {
		// token has expired, take the write lock then check again
		b.lock.RUnlock()
		// don't defer Unlock(), we want to release it ASAP
		b.lock.Lock()
		if now.Equal(b.expiresOn) || now.After(b.expiresOn) {
			// token has expired, get a new one and update shared state
			tk, err := b.creds.GetToken(ctx, b.scopes)
			if err != nil {
				b.lock.Unlock()
				return nil, err
			}
			b.expiresOn = tk.ExpiresOn
			b.header = "Bearer " + tk.Token
		} // else { another go routine already refreshed the token }
		bt = b.header
		b.lock.Unlock()
	} else {
		// token is still valid
		bt = b.header
		b.lock.RUnlock()
	}
	// no locks are to be held at this point
	req.Request.Header.Set(HeaderAuthorization, bt)
	return req.Do(ctx)
}
