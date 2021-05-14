// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azidentity

import "github.com/Azure/azure-sdk-for-go/sdk/azcore"

// AuthenticationFailedError is returned when the authentication request has failed.
type AuthenticationFailedError interface {
	azcore.NonRetriableError
	AuthenticationFailed()
}

type authenticationFailedError struct {
	error
}

// NonRetriable indicates that this error should not be retried.
func (authenticationFailedError) NonRetriable() {
	// marker method
}

func (authenticationFailedError) AuthenticationFailed() {
	// marker method
}

var _ AuthenticationFailedError = (*authenticationFailedError)(nil)

func newAuthenticationFailedError(err error) AuthenticationFailedError {
	return authenticationFailedError{err}
}

// CredentialUnavailableError is the error type returned when the conditions required to
// create a credential do not exist or are unavailable.
type CredentialUnavailableError interface {
	azcore.NonRetriableError

	// CredentialUnavailable returns the name of the credential that was unavailable.
	CredentialUnavailable() string
}

type credentialUnavailableError struct {
	credType string
	message  string
}

func (e credentialUnavailableError) Error() string {
	return e.credType + ": " + e.message
}

// NonRetriable indicates that this error should not be retried.
func (e credentialUnavailableError) NonRetriable() {
	// marker method
}

func (e credentialUnavailableError) CredentialUnavailable() string {
	return e.credType
}

var _ CredentialUnavailableError = (*credentialUnavailableError)(nil)

func newCredentialUnavailableError(credType, message string) CredentialUnavailableError {
	return credentialUnavailableError{credType: credType, message: message}
}
