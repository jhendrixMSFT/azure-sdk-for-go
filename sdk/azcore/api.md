# azcore

## Module

```text
module github.com/Azure/azure-sdk-for-go/sdk/azcore

go 1.26.0

// Direct, non-test, non-standard-library dependencies only.
require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0
)
```

## Package azcore

```go
package azcore

import (
	"context"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
)

func IsNullValue[T any](v T) bool
func NullValue[T any]() T

// Alias of github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported.AccessToken.
type AccessToken struct {
	Token     string
	ExpiresOn time.Time
	RefreshOn time.Time
}

type Client struct {
	// Contains no exported fields.
}

func NewClient(moduleName, moduleVersion string, plOpts runtime.PipelineOptions, options *ClientOptions) (*Client, error)

func (*Client) Pipeline() runtime.Pipeline
func (*Client) Tracer() tracing.Tracer
func (*Client) WithClientName(clientName string) *Client

type ClientOptions = policy.ClientOptions

type ETag string

const ETagAny ETag = "*"

func (ETag) Equals(other ETag) bool
func (ETag) IsWeak() bool
func (ETag) WeakEquals(other ETag) bool

// Alias of github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported.KeyCredential.
type KeyCredential struct {
	// Contains no exported fields.
}

func NewKeyCredential(key string) *KeyCredential

func (*KeyCredential) Update(key string)

type MatchConditions struct {
	IfMatch     *ETag
	IfNoneMatch *ETag
}

// Alias of github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported.ResponseError.
type ResponseError struct {
	ErrorCode   string
	StatusCode  int
	RawResponse *http.Response `json:"-"`
}

func (*ResponseError) Error() string
func (ResponseError) MarshalJSON() ([]byte, error)
func (*ResponseError) UnmarshalJSON(data []byte) error

// Alias of github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported.SASCredential.
type SASCredential struct {
	// Contains no exported fields.
}

func NewSASCredential(sas string) *SASCredential

func (*SASCredential) Update(sas string)

// Alias of github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported.TokenCredential.
type TokenCredential interface {
	GetToken(ctx context.Context, options policy.TokenRequestOptions) (AccessToken, error)
}
```

## Package cloud

```go
package cloud

type Configuration struct {
	ActiveDirectoryAuthorityHost string
	Services                     map[ServiceName]ServiceConfiguration
}

var (
	AzureChina = Configuration{
		ActiveDirectoryAuthorityHost: "https://login.chinacloudapi.cn/", Services: map[ServiceName]ServiceConfiguration{},
	}
	AzureGovernment = Configuration{
		ActiveDirectoryAuthorityHost: "https://login.microsoftonline.us/", Services: map[ServiceName]ServiceConfiguration{},
	}
	AzurePublic = Configuration{
		ActiveDirectoryAuthorityHost: "https://login.microsoftonline.com/", Services: map[ServiceName]ServiceConfiguration{},
	}
)

type ServiceConfiguration struct {
	Audience string
	Endpoint string
}

type ServiceName string

const ResourceManager ServiceName = "resourceManager"
```

## Package log

```go
package log

func SetEvents(cls ...Event)
func SetListener(lst func(Event, string))

// Alias of github.com/Azure/azure-sdk-for-go/sdk/internal/log.Event.
type Event string

const (
	EventLRO           Event = "LongRunningOperation"
	EventRequest       Event = "Request"
	EventResponse      Event = "Response"
	EventResponseError Event = "ResponseError"
	EventRetryPolicy   Event = "Retry"
)
```
