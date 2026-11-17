// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Package attestation enables automatic KeyGuard attestation for eligible managed
// identity mTLS proof-of-possession requests. Activate it with a blank import:
//
//	import _ "github.com/Azure/azure-sdk-for-go/sdk/azidentity/attestation"
//
// Activation is process-wide, including when imported transitively. Initialization
// only registers availability; it doesn't load native libraries, contact endpoints,
// or create keys. Unsupported hosts continue to use ordinary authentication.
// Once attested acquisition is selected, failures are returned without downgrading.
package attestation

import internalattestation "github.com/Azure/azure-sdk-for-go/sdk/azidentity/internal/attestation"

func init() {
	internalattestation.Register()
}
