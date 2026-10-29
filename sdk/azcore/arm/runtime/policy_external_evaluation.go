// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/internal/resource"
	armpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/internal/shared"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/log"
)

// LogExternalEvaluation entries contain information specific to automatic acquisition
// of Azure Policy external evaluation tokens and replay of guarded operations.
const LogExternalEvaluation log.Event = "ExternalEvaluation"

// NewExternalEvaluationPolicy creates a policy that acquires an Azure Policy external
// evaluation token when an operation is denied due to a missing token, then replays
// the operation once with the acquired token and the original serialized request body.
// If o is nil, default options are used.
func NewExternalEvaluationPolicy(cred azcore.TokenCredential, o *armpolicy.ExternalEvaluationOptions) (azpolicy.Policy, error) {
	if o == nil {
		o = &armpolicy.ExternalEvaluationOptions{}
	}
	options := o.ClientOptions
	conf, err := getConfiguration(&options)
	if err != nil {
		return nil, err
	}

	if options.APIVersion == "" {
		options.APIVersion = "2025-11-01"
	}

	// The acquire response contains a token, which must not appear in body logs.
	options.Logging.IncludeBody = false
	authPolicy := NewBearerTokenPolicy(cred, &armpolicy.BearerTokenOptions{
		AuxiliaryTenants:                o.AuxiliaryTenants,
		Scopes:                          []string{conf.Audience + "/.default"},
		InsecureAllowCredentialWithHTTP: options.InsecureAllowCredentialWithHTTP,
	})

	return &externalEvaluationPolicy{
		pipeline: runtime.NewPipeline(shared.Module, shared.Version, runtime.PipelineOptions{
			APIVersion: runtime.APIVersionOptions{Name: "api-version"},
			PerRetry:   []azpolicy.Policy{authPolicy},
		}, &options),
		apiVersion: options.APIVersion,
	}, nil
}

type externalEvaluationPolicy struct {
	pipeline   runtime.Pipeline
	apiVersion string
}

func (p *externalEvaluationPolicy) Do(req *azpolicy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if err != nil || !runtime.HasStatusCode(resp, http.StatusForbidden) {
		return resp, err
	}

	switch req.Raw().Method {
	case http.MethodDelete, http.MethodPatch, http.MethodPost, http.MethodPut:
		// only these four verbs are applicable
	default:
		return resp, nil
	}

	// Preserve caller-supplied tokens and avoid reacquisition after replay.
	// The service should already omit missingPolicyTokenDetails when a token is present.
	if req.Raw().Header.Get("x-ms-policy-external-evaluations") != "" {
		return resp, nil
	}

	var policyErr externalEvaluationError
	if err := runtime.UnmarshalAsJSON(resp, &policyErr); err != nil {
		return resp, err
	}
	if policyErr.Error == nil || !strings.EqualFold(policyErr.Error.Code, "RequestDisallowedByPolicy") {
		return resp, nil
	}

	for _, info := range policyErr.Error.AdditionalInfo {
		if info.Info.EvaluationDetails.MissingPolicyTokenDetails == nil {
			continue
		}
		res, err := resource.ParseResourceID(req.Raw().URL.Path)
		if err != nil {
			return resp, err
		}
		if res.SubscriptionID == "" {
			return resp, nil
		}
		token, err := p.acquirePolicyToken(req, res.SubscriptionID)
		if err != nil {
			return resp, fmt.Errorf("acquiring Azure Policy external evaluation token: %w", err)
		}
		if err := req.RewindBody(); err != nil {
			return resp, err
		}
		req.Raw().Header.Set("x-ms-policy-external-evaluations", token)
		return req.Next()
	}
	return resp, nil
}

func (p *externalEvaluationPolicy) acquirePolicyToken(original *azpolicy.Request, subscriptionID string) (string, error) {
	operation, err := json.Marshal(struct {
		HTTPMethod string `json:"httpMethod"`
		URI        string `json:"uri"`
	}{
		HTTPMethod: original.Raw().Method,
		URI:        original.Raw().URL.String(),
	})
	if err != nil {
		return "", err
	}

	body := append([]byte(`{"operation":`), operation[:len(operation)-1]...)
	if original.Body() != nil {
		if err := original.RewindBody(); err != nil {
			return "", err
		}
		content, readErr := io.ReadAll(original.Body())
		if err := errors.Join(readErr, original.RewindBody()); err != nil {
			return "", err
		}
		if !json.Valid(content) {
			return "", errors.New("operation content is not valid JSON")
		}
		// json.Marshal (including json.RawMessage) compacts JSON. Append the
		// serialized content directly to preserve its byte-for-byte token binding.
		body = append(body, `,"content":`...)
		body = append(body, content...)
	}
	body = append(body, '}', '}')

	endpoint := url.URL{
		Scheme: original.Raw().URL.Scheme,
		Host:   original.Raw().URL.Host,
		Path:   "/subscriptions/" + subscriptionID + "/providers/Microsoft.Authorization/acquirePolicyToken",
	}
	query := endpoint.Query()
	query.Set("api-version", p.apiVersion)
	endpoint.RawQuery = query.Encode()
	req, err := runtime.NewRequest(&shared.ContextWithDeniedValues{Context: original.Raw().Context()}, http.MethodPost, endpoint.String())
	if err != nil {
		return "", err
	}
	if err := req.SetBody(streaming.NopCloser(bytes.NewReader(body)), "application/json"); err != nil {
		return "", err
	}
	log.Write(LogExternalEvaluation, "BEGIN policy token acquisition")
	resp, err := p.pipeline.Do(req)
	if err != nil {
		return "", err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return "", runtime.NewResponseError(resp)
	}

	var result policyTokenResponse
	if err := runtime.UnmarshalAsJSON(resp, &result); err != nil {
		return "", err
	}
	if result.Result != "Succeeded" {
		return "", fmt.Errorf("policy token acquisition returned result %q: %s", result.Result, result.Message)
	}
	for _, evaluation := range result.Results {
		switch evaluation.PolicyAction {
		case "Allow", "Audit":
		default:
			return "", fmt.Errorf("policy %q returned action %q: %s",
				evaluation.PolicyInfo.PolicyAssignmentID, evaluation.PolicyAction, evaluation.PolicyEvaluationDetails.Reason)
		}
	}
	if result.Token == "" {
		return "", errors.New("policy token acquisition succeeded without a token")
	}
	log.Write(LogExternalEvaluation, "END policy token acquisition: succeeded")
	return result.Token, nil
}

type policyTokenResponse struct {
	Result  string `json:"result"`
	Message string `json:"message"`
	Token   string `json:"token"`
	Results []struct {
		PolicyAction string `json:"policyAction"`
		PolicyInfo   struct {
			PolicyAssignmentID string `json:"policyAssignmentId"`
		} `json:"policyInfo"`
		PolicyEvaluationDetails struct {
			Reason string `json:"reason"`
		} `json:"policyEvaluationDetails"`
	} `json:"results"`
}

type externalEvaluationError struct {
	Error *struct {
		Code           string `json:"code"`
		AdditionalInfo []struct {
			Info struct {
				EvaluationDetails struct {
					MissingPolicyTokenDetails *json.RawMessage `json:"missingPolicyTokenDetails"`
				} `json:"evaluationDetails"`
			} `json:"info"`
		} `json:"additionalInfo"`
	} `json:"error"`
}
