package internal

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/Azure/azure-pipeline-go/pipeline"
)

type ResponseWrapper interface {
	pipeline.Response
	Unwrap() interface{}
}

func NewResponseWrapper(r pipeline.Response, v interface{}) ResponseWrapper {
	return &responseWrapper{r: r, v: v}
}

type responseWrapper struct {
	r pipeline.Response
	v interface{}
}

func (rw responseWrapper) Response() *http.Response {
	return rw.r.Response()
}

func (rw responseWrapper) Unwrap() interface{} {
	return rw.v
}

type Responder func(resp pipeline.Response) (result pipeline.Response, err error)

// ResponderPolicyFactory is a Factory capable of creating a responder pipeline.
type ResponderPolicyFactory struct {
	Responder Responder
}

// New creates a responder policy factory.
func (rpf ResponderPolicyFactory) New(next pipeline.Policy, po *pipeline.PolicyOptions) pipeline.Policy {
	return responderPolicy{next: next, responder: rpf.Responder}
}

type responderPolicy struct {
	next      pipeline.Policy
	responder Responder
}

// Do sends the request to the service and validates/deserializes the HTTP response.
func (rp responderPolicy) Do(ctx context.Context, request pipeline.Request) (pipeline.Response, error) {
	resp, err := rp.next.Do(ctx, request)
	if err != nil {
		return resp, err
	}
	return rp.responder(resp)
}

// ValidateResponse checks an HTTP response's status code against a legal set of codes.
// If the response code is not legal, then validateResponse reads all of the response's body
// (containing error information) and returns a response error.
func ValidateResponse(resp pipeline.Response, successStatusCodes ...int) error {
	if resp == nil {
		return errors.New("nil response") //NewResponseError(nil, nil, "nil response")
	}
	responseCode := resp.Response().StatusCode
	for _, i := range successStatusCodes {
		if i == responseCode {
			return nil
		}
	}
	// only close the body in the failure case. in the
	// success case responders will close the body as required.
	defer resp.Response().Body.Close()
	b, err := ioutil.ReadAll(resp.Response().Body)
	if err != nil {
		return errors.New("failed to read response body") //NewResponseError(err, resp.Response(), "failed to read response body")
	}
	// the service code, description and details will be populated during unmarshalling
	responseError := errors.New("nil response") //NewResponseError(nil, resp.Response(), resp.Response().Status)
	if len(b) > 0 {
		if err = json.Unmarshal(b, &responseError); err != nil {
			return errors.New("failed to unmarshal response body") //NewResponseError(err, resp.Response(), "failed to unmarshal response body")
		}
	}
	return responseError
}
