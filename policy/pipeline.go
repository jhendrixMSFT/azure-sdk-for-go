package policy

import (
	"context"

	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/satori/go.uuid"
)

// NewPipeline creates a Pipeline using the specified credentials and options.
func NewPipeline(c Credential, o pipeline.Options) pipeline.Pipeline {
	if c == nil {
		panic("c can't be nil")
	}

	// policy factories and their associated policies are executed in the order defined here
	f := []pipeline.Factory{
		NewUniqueRequestIDPolicyFactory(),
		NewRetryPolicyFactory(),
		c,
		pipeline.MethodFactoryMarker(),
	}

	return pipeline.NewPipeline(f, o)
}

// NewUniqueRequestIDPolicyFactory creates a UniqueRequestIDPolicyFactory object
// that sets the request's x-ms-client-request-id header if it doesn't already exist.
func NewUniqueRequestIDPolicyFactory() pipeline.Factory {
	return pipeline.FactoryFunc(func(next pipeline.Policy, po *pipeline.PolicyOptions) pipeline.PolicyFunc {
		// This is Policy's Do method:
		return func(ctx context.Context, request pipeline.Request) (pipeline.Response, error) {
			id := request.Header.Get("x-ms-client-request-id")
			if id == "" { // Add a unique request ID if the caller didn't specify one already
				request.Header.Set("x-ms-client-request-id", uuid.NewV4().String())
			}
			return next.Do(ctx, request)
		}
	})
}

// NewRetryPolicyFactory creates a RetryPolicyFactory object.
func NewRetryPolicyFactory() pipeline.Factory {
	return pipeline.FactoryFunc(func(next pipeline.Policy, po *pipeline.PolicyOptions) pipeline.PolicyFunc {
		return func(ctx context.Context, request pipeline.Request) (pipeline.Response, error) {
			// TODO: no retries!
			return next.Do(ctx, request)
		}
	})
}
