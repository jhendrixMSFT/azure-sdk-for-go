# Managed identity mTLS PoP smoke test

This standalone, read-only app verifies the local `azidentity` and `azcore` changes
against [MSAL's IMDSv2/mTLS PoP flow](https://github.com/AzureAD/microsoft-authentication-library-for-go/pull/662)
using MSAL v1.11.0-beta.1. Both SDK modules are replaced with this checkout;
replacements in a dependency's `go.mod` aren't inherited by an application.
The executable checks these replacements in its build metadata.

The live smoke test is run on demand when a compatible VM and service fixture
are available. It is not intended for normal CI or weekly live CI, which cannot
assume those prerequisites. Fixture-free tests in the SDK module suites provide
the routine regression coverage described below.

## Prerequisites

- Go 1.26 or later to build.
- Run on an Azure Windows VM with Credential Guard/VBS and KeyGuard available,
  native IMDSv2, and an assigned managed identity. Trusted Launch or Confidential
  VM configuration alone isn't proof that all these capabilities are enabled.
- An existing **public Azure** Key Vault configured to accept certificate-bound
  tokens and an existing test secret. Ordinary Key Vault availability does not
  establish that token binding is enabled. Use an approved mTLS PoP fixture.
- The identity needs permission to get that secret, for example the Key Vault
  Secrets User role, and network access to the vault, IMDS, and Entra.
- No managed identity source override environment variables. The app refuses
  `IDENTITY_*`, `IMDS_ENDPOINT`, `MSI_*`, `AZURE_POD_IDENTITY_AUTHORITY_HOST`,
  and `MSAL_MI_DISABLE_IMDS_V2` settings that could select another source or
  disable the feature. Run in a clean shell; the app doesn't clear variables.
  Configure `NO_PROXY` for `169.254.169.254` if your environment uses a proxy.

The app doesn't provision or modify Azure resources. MSAL may create a
VBS-isolated key and persist its issued certificate in the current user's
Windows certificate store. Don't export the private key, close its handle,
or delete a shared certificate/key container to obtain a cold-cache run.

## Test tenant and identity setup

Tenant access alone isn't sufficient. Follow the feature team's onboarding
instructions to obtain an IMDSv2-capable Windows VM and a token-binding-enabled
Key Vault in the test tenant. Generic VM or vault provisioning doesn't establish
that these preview capabilities are enabled.

From an administrative workstation with Azure CLI installed, select the test
tenant and subscription:

```powershell
az login --tenant "<test-tenant-id>"
az account set --subscription "<test-subscription-id>"
```

For a system-assigned identity, enable it on the test VM if necessary and obtain
its principal ID:

```powershell
az vm identity assign -g "<vm-resource-group>" -n "<vm-name>" --output none

$principalID = az vm show `
    -g "<vm-resource-group>" -n "<vm-name>" `
    --query identity.principalId -o tsv

$vaultID = az keyvault show --name "<vault-name>" --query id -o tsv
```

For an **RBAC-enabled** test vault, grant that identity permission to read secrets:

```powershell
az role assignment create `
    --assignee-object-id $principalID `
    --assignee-principal-type ServicePrincipal `
    --role "Key Vault Secrets User" `
    --scope $vaultID `
    --output none
```

Check that each Azure CLI command succeeds before proceeding. Allow time for RBAC
propagation. If the vault uses access policies instead of RBAC, grant the identity
the secret **Get** permission through an access policy. Use an existing,
non-sensitive test secret.

For a user-assigned identity, ensure it is attached to the VM and grant its
principal ID the same vault access instead. Obtain its `principalId` and
`clientId` with `az identity show -g "<identity-resource-group>" -n "<identity-name>"`.
Pass the **client ID**, not the principal ID, to the app's `-client-id` flag.

The app runs **on the VM** and authenticates as its managed identity, not the
Azure CLI account. It doesn't need Azure CLI on the VM, a client secret, or a
tenant-ID argument.

If IMDS requires attested issuance, pass `-attestation` to set
`ManagedIdentityCredentialOptions.EnableAttestation`. Deploy `AttestationClientLib.dll`
from the `Microsoft.Azure.Security.KeyGuardAttestation` package
(`runtimes/win-x64/native`) alongside the executable or into System32, and install
the [x64 Microsoft Visual C++ 2015-2022 Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist).
The DLL isn't loaded from the working directory or `PATH`. Attestation is disabled
by default; deploying the DLL alone doesn't enable it. When enabled, attestation
failures fail acquisition without falling back to an unattested credential.
Ordinary bearer requests remain unchanged.

## Build and run

From this directory in the current checkout, including the challenge
authentication fix:

```powershell
go test -count=1 ./...
go build -trimpath -o .\mtls-pop-smoke.exe .
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

# System-assigned identity
.\mtls-pop-smoke.exe `
    -vault-url "https://<vault-name>.vault.azure.net" `
    -secret-name "<existing-test-secret>"

# User-assigned identity attached to this VM
.\mtls-pop-smoke.exe `
    -vault-url "https://<vault-name>.vault.azure.net" `
    -secret-name "<existing-test-secret>" `
    -client-id "<managed-identity-client-id>"
```

Alternatively select a user-assigned identity with `-object-id` or `-resource-id`.
Only one identity selector is permitted. Add `-attestation` to either command
when IMDS requires key attestation. The default overall timeout is five
minutes; override with `-timeout 10m`. To build elsewhere and copy to the VM,
preserve the two relative module replacements and build with `GOOS=windows`
and the VM's `GOARCH`. The VM doesn't need Go to run the executable.
Copy the newly built executable to the VM and run it there from a clean
PowerShell session. Check `$LASTEXITCODE` immediately after the app exits.

## Required results

Every check must pass, the process must exit zero, and the final message must be
`PASS: all mTLS PoP smoke checks`:

1. Ordinary token acquisition returns a nonempty, unexpired bearer token without
   a binding certificate.
2. `GetToken` with `policy.TokenRequestOptions.EnableMTLSPoP` returns a live
   binding certificate and matching private-key public component.
   The token's `cnf.x5t#S256` must equal the leaf certificate's SHA-256 thumbprint.
3. A direct HTTPS secret GET succeeds with `Authorization: mtls_pop`,
   `x-ms-tokenboundauth: true`, and the binding certificate.
4. The **same token**, same URL, and same headers on a fresh connection with
   **no certificate** produce a 4xx response naming `MissingClientCertificate`.
   A timeout, TLS failure, redirect, unrelated 403, or 5xx doesn't pass.
5. A subsequent ordinary acquisition on the same credential remains unbound,
   checking bearer/PoP cache isolation without assuming exact token reuse.
6. A fresh `azsecrets.Client` with embedded
   `azcore.ClientOptions{EnableMTLSPoP: true}` reads the secret twice.
   A credential wrapper requires propagation of the PoP flag and validates every
   token the SDK requests. The client starts cold, including its initial
   unauthenticated Key Vault challenge; the app doesn't pre-seed that challenge
   or silently replace it with a hand-built pipeline.

JWT decoding checks the binding claim, **not the signature**. The resource
requests establish server acceptance and enforcement. Token strings, private
keys, secret values, and HTTP bodies aren't printed. A public certificate
thumbprint and token expiry are printed for correlation. Failed direct resource
requests report only the HTTP status and Key Vault error and inner error codes,
not the error message or response body.

The direct resource transport uses TLS 1.2, client renegotiation, and
`GetClientCertificate`, as required by the MSAL sample. Server certificate
verification remains enabled and redirects are refused. The automatic path
leaves this transport configuration to `azcore`.

## Failure interpretation

- Acquisition failure: inspect Windows Credential Guard/KeyGuard, IMDSv2,
  identity assignment, Entra connectivity, and resource opt-in. Unsupported hosts
  fail; there's no fallback to another credential.
- IMDS reports "Attestation Token is missing / empty": rebuild and run with
  `-attestation`, with the attestation DLL and x64 Visual C++ runtime installed.
  If attestation itself fails, inspect the reported native-library or attestation
  error rather than disabling attestation.
- Direct request HTTP 403/404: check token-binding opt-in, network restrictions,
  RBAC propagation, and secret existence. Use the reported Key Vault error and
  inner error codes to distinguish authorization or network denials from
  certificate-binding rejection. A successful token request alone does not
  verify resource access.
- Missing-certificate request succeeds: token binding isn't being enforced.
- Missing-certificate request fails for another reason: inconclusive, not a pass.
- Automatic SDK request fails before requesting a token: the resource client's
  challenge/pipeline integration is failing even if the direct request passed.

Offline unit tests exercise certificate/claim validation, rejection criteria,
TLS and headers, redirects, SDK flag checking, and local-module guards. They
don't prove that a machine has IMDSv2, a real KeyGuard key, or a token-binding
enabled vault. A live run on the fixture is required for end-to-end verification.

### Challenge authentication regression coverage

The offline `TestKeyVaultSDKColdChallenge` test runs the real `azsecrets.Client`
against a local TLS server. It requires one certificate-free, unauthenticated
challenge followed by two successful, certificate-authenticated secret reads,
with the PoP flag reaching the credential and its token cached.

The [mTLS transport](../../../azcore/runtime/policy_mtls.go) isolates the initial
challenge in its own certificate-free connection pool. Authenticated requests
still require a binding certificate; challenge requests retain HTTPS enforcement,
server certificate verification, redirect rejection, and transport validation.
This covers the failure originally reproduced on HEAD `dd45fa1ed0`, where the
initial challenge failed before the credential was called.

### Offline regression coverage in normal CI

The standalone app and its tests are intentionally in a nested module under
`testdata`. Ordinary module `go test ./...` and SDK CI discovery do not include
that module; the hardware-backed smoke test remains an on-demand check, not a
CI prerequisite.
The following fixture-free regressions are in the normal SDK module suites:

- `azidentity`: attestation and PoP option propagation, binding-certificate
  propagation, failure without downgrade, and certificate-scoped acquisition
  pipelines that preserve middleware and caller-owned transports.
- `azidentity`: on Windows, real MSAL IMDSv2 metadata requests select the requested
  client, object, or resource ID (or the system-assigned identity). A mocked
  metadata rejection stops the test before native key creation, attestation, or
  certificate-store access, and must not trigger an IMDSv1 fallback.
- `azcore/runtime`: certificate-free cold challenges followed by bound requests,
  authorization scheme and binding headers, CAE challenges, concurrent cached
  requests, bearer/PoP cache isolation, certificate expiration, redirects,
  server trust, and unsupported transports.
- `azcore/runtime`: forcing SDK cache reacquisition switches the certificate
  actually presented on the TLS connection. A retried 503 and a subsequent
  cached request retain the renewed token/certificate pair. This is synthetic
  certificate replacement, not proof of real IMDS/Entra renewal or rotation.

Run the focused suites from their respective module directories:

```powershell
# sdk\azidentity
go test -count=1 -run 'MTLSPoP|Attestation|BindingCertificate|MTLSFactory' .

# sdk\azcore
go test -count=1 -run MTLSPoP ./runtime ./arm/runtime
```

These tests need no managed identity, Azure permissions, attestation DLL, or
token-binding-enabled vault. They guard SDK integration behavior without relying
on the availability of the live fixture. They cannot establish native KeyGuard
availability, successful MAA attestation, real certificate issuance/rotation, or
service-side binding enforcement. Preserve a successful live smoke run as
separate evidence, and repeat it for release or authentication-dependency
changes when the fixture is available.
