# Azure Identity attestation integration for Go

This optional module enables automatic KeyGuard attestation for eligible managed identity
mTLS proof-of-possession (PoP) requests made through `ManagedIdentityCredential` or
`DefaultAzureCredential`. Native attestation is implemented by MSAL.

This feature is unreleased. For local builds, use application-level replacements for this
module, `azidentity`, and `azcore`, as shown by the
[on-demand smoke app](../testdata/mtls-pop-smoke/README.md). The releasable module contains
no local replacements.

## Activate the integration

Add a documented blank import to your application and construct credentials normally:

```go
import (
    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    _ "github.com/Azure/azure-sdk-for-go/sdk/azidentity/attestation"
)

cred, err := azidentity.NewDefaultAzureCredential(nil)
if err != nil {
    // handle error
}
```

Activation is process-wide, including when imported transitively. Adding a requirement to
`go.mod` alone doesn't activate the integration. Initialization only records availability:
it doesn't load native libraries, contact endpoints, or create keys. Credentials constructed
during package initialization also consult availability lazily when requesting tokens.

## Request selection

Attested acquisition requires all of the following:

- The integration is imported.
- The token request signals mTLS PoP support.
- Managed identity PoP isn't disabled.
- MSAL successfully discovers a host supporting mTLS PoP with at least KeyGuard binding strength.

Updated Key Vault clients signal PoP support automatically; construct them with ordinary
options, for example `azsecrets.NewClient(vaultURL, cred, nil)`. Other resource clients
can signal support with `ClientOptions.EnableMTLSPoP: true`.
Direct token callers set `policy.TokenRequestOptions.EnableMTLSPoP` and inspect the returned
`AccessToken.BindingCertificate` to determine whether bearer or mTLS PoP authorization is required.
See the [identity documentation](../README.md#managed-identity-mtls-proof-of-possession)
for transport requirements.

Ordinary bearer requests are unchanged. Without activation, when opted out, or when discovery
successfully identifies an unsupported host, managed identity uses ordinary bearer acquisition.
The package can be imported on unsupported platforms. Discovery failures aren't treated as
known lack of support. Once attested acquisition is selected, the credential returns failures
without retrying unattested acquisition or continuing to another credential.

The [Key Vault policy](../../security/keyvault/internal/README.md) handles the specifically
classified tenant denial `AADSTS3921996` by acquiring a fresh bearer token and remembering
the decision per tenant for that client. This isn't permission to downgrade for native
attestation failures, cancellation, RBAC denials, network failures, or unsupported transports.
The specific bound-token validation HTTP 401 is retried under the configured outer retry policy.

To opt out on an individual managed identity credential, set
`ManagedIdentityCredentialOptions.DisableMTLSPoP: true`. No additional public attestation
option is required on `DefaultAzureCredential`.

## Native prerequisites

Attested acquisition currently requires a Windows VM with Credential Guard/KeyGuard and IMDSv2.
Deploy `AttestationClientLib.dll` from the `Microsoft.Azure.Security.KeyGuardAttestation`
package (`runtimes/win-x64/native`) alongside the executable or into System32. Install the
[x64 Microsoft Visual C++ 2015-2022 Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist).
The DLL isn't loaded from the working directory or `PATH`. Deploying the DLL alone doesn't
activate the integration. A missing or unusable native dependency after selection is an
acquisition error, not permission to fall back to bearer.
