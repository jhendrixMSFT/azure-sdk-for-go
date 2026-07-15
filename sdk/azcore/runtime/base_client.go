package runtime

import (
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/shared"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/tracing"
)

// BaseClient is a SDK base client type.  It consists of an endpoint, pipeline and tracing provider.
// It can also contain client-specific state via its generic type parameter T.
type BaseClient[T any] struct {
	pl Pipeline
	tr tracing.Tracer

	// cached on the client to support shallow copying with new values
	tp        tracing.Provider
	modVer    string
	namespace string

	endpoint string
	state    T
}

// Endpoint returns the endpoint for this client.
func (c *BaseClient[T]) Endpoint() string {
	return c.endpoint
}

// Pipeline returns the pipeline for this client.
func (c *BaseClient[T]) Pipeline() Pipeline {
	return c.pl
}

// State returns any client-specific state for this client.
func (c *BaseClient[T]) State() T {
	return c.state
}

// Tracer returns the tracer for this client.
func (c *BaseClient[T]) Tracer() tracing.Tracer {
	return c.tr
}

// WithClientName returns a shallow copy of the Client with its tracing client name changed to clientName.
// Note that the values for module name and version will be preserved from the source Client.
//   - clientName - the fully qualified name of the client ("package.Client"); this is used by the tracing provider when creating spans
func (c *BaseClient[T]) WithClientName(clientName string) *BaseClient[T] {
	tr := c.tp.NewTracer(clientName, c.modVer)
	if tr.Enabled() && c.namespace != "" {
		tr.SetAttributes(tracing.Attribute{Key: shared.TracingNamespaceAttrName, Value: c.namespace})
	}
	return &BaseClient[T]{
		pl:        c.pl,
		tr:        tr,
		tp:        c.tp,
		modVer:    c.modVer,
		namespace: c.namespace,
		endpoint:  c.endpoint,
		state:     c.state,
	}
}

// NewClient creates a new Client instance with the provided values.
//   - moduleName - the fully qualified name of the module where the client is defined; used by the telemetry policy and tracing provider.
//   - moduleVersion - the semantic version of the module; used by the telemetry policy and tracing provider.
//   - plOpts - pipeline configuration options; can be the zero-value
//   - options - optional client configurations; pass nil to accept the default values
func NewBaseClient[T any](endpoint, moduleName, moduleVersion string, plOpts PipelineOptions, state T, options *policy.ClientOptions) (*BaseClient[T], error) {
	if options == nil {
		options = &policy.ClientOptions{}
	}

	if !options.Telemetry.Disabled {
		if err := shared.ValidateModVer(moduleVersion); err != nil {
			return nil, err
		}
	}

	pl := NewPipeline(moduleName, moduleVersion, plOpts, options)

	tr := options.TracingProvider.NewTracer(moduleName, moduleVersion)
	if tr.Enabled() && plOpts.Tracing.Namespace != "" {
		tr.SetAttributes(tracing.Attribute{Key: shared.TracingNamespaceAttrName, Value: plOpts.Tracing.Namespace})
	}

	return &BaseClient[T]{
		pl:        pl,
		tr:        tr,
		tp:        options.TracingProvider,
		modVer:    moduleVersion,
		namespace: plOpts.Tracing.Namespace,
		endpoint:  endpoint,
		state:     state,
	}, nil
}
