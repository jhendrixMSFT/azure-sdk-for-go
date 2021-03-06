// Package personalizer implements the Azure ARM Personalizer service API version v1.0.
//
// Personalizer Service is an Azure Cognitive Service that makes it easy to target content and experiences without
// complex pre-analysis or cleanup of past data. Given a context and featurized content, the Personalizer Service
// returns which content item to show to users in rewardActionId. As rewards are sent in response to the use of
// rewardActionId, the reinforcement learning algorithm will improve the model and improve performance of future rank
// calls.
package personalizer

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/validation"
	"github.com/Azure/go-autorest/tracing"
	"net/http"
)

// BaseClient is the base client for Personalizer.
type BaseClient struct {
	autorest.Client
	Endpoint string
}

// New creates an instance of the BaseClient client.
func New(endpoint string) BaseClient {
	return NewWithoutDefaults(endpoint)
}

// NewWithoutDefaults creates an instance of the BaseClient client.
func NewWithoutDefaults(endpoint string) BaseClient {
	return BaseClient{
		Client:   autorest.NewClientWithUserAgent(UserAgent()),
		Endpoint: endpoint,
	}
}

// Rank submit a Personalizer rank request, to get which of the provided actions should be used in the provided
// context.
// Parameters:
// rankRequest - a Personalizer request.
func (client BaseClient) Rank(ctx context.Context, rankRequest RankRequest) (result RankResponse, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/BaseClient.Rank")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: rankRequest,
			Constraints: []validation.Constraint{{Target: "rankRequest.Actions", Name: validation.Null, Rule: true, Chain: nil},
				{Target: "rankRequest.EventID", Name: validation.Null, Rule: false,
					Chain: []validation.Constraint{{Target: "rankRequest.EventID", Name: validation.MaxLength, Rule: 256, Chain: nil}}}}}}); err != nil {
		return result, validation.NewError("personalizer.BaseClient", "Rank", err.Error())
	}

	req, err := client.RankPreparer(ctx, rankRequest)
	if err != nil {
		err = autorest.NewErrorWithError(err, "personalizer.BaseClient", "Rank", nil, "Failure preparing request")
		return
	}

	resp, err := client.RankSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "personalizer.BaseClient", "Rank", resp, "Failure sending request")
		return
	}

	result, err = client.RankResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "personalizer.BaseClient", "Rank", resp, "Failure responding to request")
	}

	return
}

// RankPreparer prepares the Rank request.
func (client BaseClient) RankPreparer(ctx context.Context, rankRequest RankRequest) (*http.Request, error) {
	urlParameters := map[string]interface{}{
		"Endpoint": client.Endpoint,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsContentType("application/json; charset=utf-8"),
		autorest.AsPost(),
		autorest.WithCustomBaseURL("{Endpoint}/personalizer/v1.0", urlParameters),
		autorest.WithPath("/rank"),
		autorest.WithJSON(rankRequest))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// RankSender sends the Rank request. The method will close the
// http.Response Body if it receives an error.
func (client BaseClient) RankSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
}

// RankResponder handles the response to the Rank request. The method always
// closes the http.Response Body.
func (client BaseClient) RankResponder(resp *http.Response) (result RankResponse, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusCreated),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}
