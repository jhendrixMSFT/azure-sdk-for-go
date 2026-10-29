// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	armpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/exported"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
	"github.com/stretchr/testify/require"
)

func TestExternalEvaluationPolicyDetection(t *testing.T) {
	const actionable = `{"error":{"code":"RequestDisallowedByPolicy","additionalInfo":[{"info":{}},{"info":{"evaluationDetails":{"missingPolicyTokenDetails":{}}}}]}}`
	const subscriptionPath = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Test/widgets/widget"
	for _, tt := range []struct {
		name         string
		method       string
		status       int
		body         string
		path         string
		token        string
		wantErr      string
		wantRequests int
	}{
		{name: "PUT", method: http.MethodPut, wantRequests: 3},
		{name: "PATCH", method: http.MethodPatch, wantRequests: 3},
		{name: "POST", method: http.MethodPost, wantRequests: 3},
		{name: "bodyless DELETE", method: http.MethodDelete, wantRequests: 3},
		{name: "GET", method: http.MethodGet},
		{name: "HEAD", method: http.MethodHead},
		{name: "success", status: http.StatusOK},
		{name: "conflict", status: http.StatusConflict},
		{name: "existing token", token: "PoP token"},
		{name: "management group", path: "/providers/Microsoft.Management/managementGroups/group"},
		{name: "missing error", body: `{}`},
		{name: "null error", body: `{"error":null}`},
		{name: "unrelated error", body: `{"error":{"code":"AuthorizationFailed","additionalInfo":[{"info":{"evaluationDetails":{"missingPolicyTokenDetails":{}}}}]}}`},
		{name: "missing additional info", body: `{"error":{"code":"RequestDisallowedByPolicy"}}`},
		{name: "missing evaluation details", body: `{"error":{"code":"RequestDisallowedByPolicy","additionalInfo":[{"info":{}}]}}`},
		{name: "null token details", body: `{"error":{"code":"RequestDisallowedByPolicy","additionalInfo":[{"info":{"evaluationDetails":{"missingPolicyTokenDetails":null}}}]}}`},
		{name: "malformed response", body: `{`, wantErr: "unmarshalling"},
		{name: "invalid resource ID", path: "/invalid", wantErr: "invalid resource ID"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.method == "" {
				tt.method = http.MethodPut
			}
			if tt.status == 0 {
				tt.status = http.StatusForbidden
			}
			if tt.body == "" {
				tt.body = actionable
			}
			if tt.path == "" {
				tt.path = subscriptionPath
			}
			srv, close := mock.NewTLSServer()
			defer close()
			srv.AppendResponse(mock.WithStatusCode(tt.status), mock.WithBody([]byte(tt.body)))
			srv.AppendResponse(mock.WithBody([]byte(`{"result":"Succeeded","token":"PoP token"}`)))
			srv.AppendResponse(mock.WithStatusCode(tt.status), mock.WithBody([]byte(tt.body)))
			p, err := NewExternalEvaluationPolicy(mockCredential{}, &armpolicy.ExternalEvaluationOptions{
				ClientOptions: azpolicy.ClientOptions{Transport: srv},
			})
			require.NoError(t, err)
			pl := runtime.NewPipeline("test", "v0.1.0", runtime.PipelineOptions{
				PerCall: []azpolicy.Policy{p},
			}, &azpolicy.ClientOptions{Transport: srv})
			req, err := runtime.NewRequest(context.Background(), tt.method, srv.URL()+tt.path)
			require.NoError(t, err)
			if tt.token != "" {
				req.Raw().Header.Set("x-ms-policy-external-evaluations", tt.token)
			}
			resp, err := pl.Do(req)
			expectedRequests := tt.wantRequests
			if expectedRequests == 0 {
				expectedRequests = 1
			}
			require.Equal(t, expectedRequests, srv.Requests(), "must not acquire again after a replayed 403")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.status, resp.StatusCode)
			body, err := runtime.Payload(resp)
			require.NoError(t, err)
			if tt.method == http.MethodHead {
				require.Empty(t, body)
			} else {
				require.Equal(t, tt.body, string(body))
			}
		})
	}
}

type externalEvaluationTransport func(*http.Request) (*http.Response, error)

func (f externalEvaluationTransport) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

const externalEvaluationDenied = `{"error":{"code":"RequestDisallowedByPolicy","additionalInfo":[{"info":{"evaluationDetails":{"missingPolicyTokenDetails":{}}}}]}}`

func TestExternalEvaluationPolicyAcquireAndReplay(t *testing.T) {
	for _, tt := range []struct {
		name       string
		method     string
		content    string
		apiVersion string
	}{
		{name: "PUT exact bytes", method: http.MethodPut, content: " \r\n{ \"z\": 1.00, \"a\": \"\\u0061 <>&\", \"b\": null }\r\n "},
		{name: "PATCH", method: http.MethodPatch, content: "{\n \"tags\": { \"x\": \"y\" }\n}"},
		{name: "POST", method: http.MethodPost, content: `{"value":1e2}`},
		{name: "bodyless DELETE", method: http.MethodDelete},
		{name: "API version override", method: http.MethodPut, content: `{}`, apiVersion: "2099-01-01"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const endpoint = "https://management.example.test/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Test/widgets/widget?api-version=2025-01-01"
			const token = "PoP secret-policy-token"
			const tokenID = "secret-token-id"
			var entries []string
			log.SetEvents(log.EventRequest, log.EventResponse, LogExternalEvaluation)
			log.SetListener(func(_ log.Event, message string) { entries = append(entries, message) })
			defer func() {
				log.SetListener(nil)
				log.SetEvents()
			}()
			requests := 0
			transport := externalEvaluationTransport(func(req *http.Request) (*http.Response, error) {
				requests++
				var body []byte
				if req.Body != nil {
					var err error
					body, err = io.ReadAll(req.Body)
					require.NoError(t, err)
				}
				status, responseBody := http.StatusOK, `{}`
				switch requests {
				case 1:
					require.Equal(t, endpoint, req.URL.String())
					require.Equal(t, tt.content, string(body))
					status, responseBody = http.StatusForbidden, externalEvaluationDenied
				case 2:
					require.Equal(t, http.MethodPost, req.Method)
					require.Equal(t, "management.example.test", req.URL.Host)
					require.Equal(t, "/subscriptions/sub/providers/Microsoft.Authorization/acquirePolicyToken", req.URL.Path)
					version := tt.apiVersion
					if version == "" {
						version = "2025-11-01"
					}
					require.Equal(t, version, req.URL.Query().Get("api-version"))
					require.Equal(t, "Bearer ***", req.Header.Get("Authorization"))
					require.Equal(t, "application/json", req.Header.Get("Content-Type"))
					var decoded struct {
						Operation struct {
							HTTPMethod string          `json:"httpMethod"`
							URI        string          `json:"uri"`
							Content    json.RawMessage `json:"content"`
						} `json:"operation"`
					}
					require.NoError(t, json.Unmarshal(body, &decoded))
					require.Equal(t, tt.method, decoded.Operation.HTTPMethod)
					require.Equal(t, endpoint, decoded.Operation.URI)
					if tt.content == "" {
						require.Nil(t, decoded.Operation.Content)
					} else {
						marker := []byte(`,"content":`)
						start := bytes.Index(body, marker)
						require.NotEqual(t, -1, start)
						require.Equal(t, tt.content, string(body[start+len(marker):len(body)-2]))
					}
					responseBody = `{"result":"Succeeded","token":"` + token + `","tokenId":"` + tokenID + `","results":[{"policyAction":"Allow"},{"policyAction":"Audit"}]}`
				case 3:
					require.Equal(t, endpoint, req.URL.String())
					require.Equal(t, tt.method, req.Method)
					require.Equal(t, token, req.Header.Get("x-ms-policy-external-evaluations"))
					require.Equal(t, tt.content, string(body))
				default:
					t.Fatalf("unexpected request %d", requests)
				}
				return &http.Response{
					StatusCode: status,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(responseBody)),
					Request:    req,
				}, nil
			})
			options := armpolicy.ExternalEvaluationOptions{ClientOptions: azpolicy.ClientOptions{
				Transport:  transport,
				APIVersion: tt.apiVersion,
				Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
					cloud.ResourceManager: {Endpoint: "https://management.example.test", Audience: "https://management.example.test"},
				}},
				Logging: azpolicy.LogOptions{IncludeBody: true},
			}}
			p, err := NewExternalEvaluationPolicy(mockCredential{}, &options)
			require.NoError(t, err)
			require.True(t, options.Logging.IncludeBody, "constructor must not mutate caller's options")
			pl := runtime.NewPipeline("test", "v0.1.0", runtime.PipelineOptions{PerCall: []azpolicy.Policy{p}},
				&azpolicy.ClientOptions{Transport: transport, Logging: options.Logging})
			req, err := runtime.NewRequest(context.Background(), tt.method, endpoint)
			require.NoError(t, err)
			if tt.content != "" {
				require.NoError(t, req.SetBody(streaming.NopCloser(strings.NewReader(tt.content)), "application/json"))
			}
			resp, err := pl.Do(req)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, 3, requests)
			require.NotContains(t, strings.Join(entries, "\n"), token)
			require.NotContains(t, strings.Join(entries, "\n"), tokenID)
		})
	}
}

func TestExternalEvaluationPolicyAcquireFailures(t *testing.T) {
	for _, tt := range []struct {
		name    string
		status  int
		body    string
		content string
		wantErr string
	}{
		{name: "HTTP failure", status: http.StatusForbidden, body: `{"error":{"code":"AuthorizationFailed","message":"not permitted"}}`, wantErr: "AuthorizationFailed"},
		{name: "failed result", body: `{"result":"Failed","message":"evaluation failed"}`, wantErr: "evaluation failed"},
		{name: "denied", body: `{"result":"Succeeded","results":[{"policyAction":"Deny","policyInfo":{"policyAssignmentId":"assignment"},"policyEvaluationDetails":{"reason":"blocked"}}]}`, wantErr: `policy "assignment" returned action "Deny": blocked`},
		{name: "evaluation error", body: `{"result":"Succeeded","results":[{"policyAction":"Error","policyEvaluationDetails":{"reason":"query failed"}}]}`, wantErr: "query failed"},
		{name: "unknown action", body: `{"result":"Succeeded","token":"PoP token","results":[{"policyAction":"Unknown"}]}`, wantErr: `action "Unknown"`},
		{name: "missing token", body: `{"result":"Succeeded"}`, wantErr: "succeeded without a token"},
		{name: "unknown result", body: `{"result":"Other","token":"PoP token"}`, wantErr: `result "Other"`},
		{name: "empty response", body: ``, wantErr: `result ""`},
		{name: "invalid response", body: `{`, wantErr: "unmarshalling"},
		{name: "invalid content", content: "invalid JSON", wantErr: "operation content is not valid JSON"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv, close := mock.NewTLSServer()
			defer close()
			srv.AppendResponse(mock.WithStatusCode(http.StatusForbidden), mock.WithBody([]byte(externalEvaluationDenied)))
			status := tt.status
			if status == 0 {
				status = http.StatusOK
			}
			srv.AppendResponse(mock.WithStatusCode(status), mock.WithBody([]byte(tt.body)))
			p, err := NewExternalEvaluationPolicy(mockCredential{}, &armpolicy.ExternalEvaluationOptions{
				ClientOptions: azpolicy.ClientOptions{Transport: srv},
			})
			require.NoError(t, err)
			pl := runtime.NewPipeline("test", "v0.1.0", runtime.PipelineOptions{PerCall: []azpolicy.Policy{p}},
				&azpolicy.ClientOptions{Transport: srv})
			req, err := runtime.NewRequest(context.Background(), http.MethodPut, srv.URL()+"/subscriptions/sub/providers/Microsoft.Test/widgets/widget")
			require.NoError(t, err)
			if tt.content != "" {
				require.NoError(t, req.SetBody(streaming.NopCloser(strings.NewReader(tt.content)), "application/json"))
			}
			_, err = pl.Do(req)
			require.ErrorContains(t, err, tt.wantErr)
			expectedRequests := 2
			if tt.content != "" {
				expectedRequests = 1
			}
			require.Equal(t, expectedRequests, srv.Requests(), "acquisition failure must not replay the operation")
		})
	}
}

func TestExternalEvaluationPolicyTransportError(t *testing.T) {
	wantErr := errors.New("transport failed")
	pl := runtime.NewPipeline("test", "v0.1.0", runtime.PipelineOptions{
		PerCall: []azpolicy.Policy{&externalEvaluationPolicy{}, exported.PolicyFunc(func(*azpolicy.Request) (*http.Response, error) {
			return nil, wantErr
		})},
	}, nil)
	req, err := runtime.NewRequest(context.Background(), http.MethodPut, "https://management.azure.com/subscriptions/sub")
	require.NoError(t, err)
	resp, err := pl.Do(req)
	require.ErrorIs(t, err, wantErr)
	require.Nil(t, resp)
}

func TestExternalEvaluationPolicyAcquireTransportError(t *testing.T) {
	wantErr := errors.New("acquisition transport failed")
	var acquisitionRequests int
	p, err := NewExternalEvaluationPolicy(mockCredential{}, &armpolicy.ExternalEvaluationOptions{
		ClientOptions: azpolicy.ClientOptions{
			Retry: azpolicy.RetryOptions{MaxRetries: -1},
			Transport: externalEvaluationTransport(func(req *http.Request) (*http.Response, error) {
				acquisitionRequests++
				return nil, wantErr
			}),
		},
	})
	require.NoError(t, err)
	srv, close := mock.NewTLSServer()
	defer close()
	srv.AppendResponse(mock.WithStatusCode(http.StatusForbidden), mock.WithBody([]byte(externalEvaluationDenied)))
	pl := runtime.NewPipeline("test", "v0.1.0", runtime.PipelineOptions{PerCall: []azpolicy.Policy{p}},
		&azpolicy.ClientOptions{Transport: srv})
	req, err := runtime.NewRequest(context.Background(), http.MethodPut, srv.URL()+"/subscriptions/sub/providers/Microsoft.Test/widgets/widget")
	require.NoError(t, err)
	_, err = pl.Do(req)
	require.ErrorIs(t, err, wantErr)
	require.Equal(t, 1, acquisitionRequests)
	require.Equal(t, 1, srv.Requests(), "must not replay after a transport failure")
}
