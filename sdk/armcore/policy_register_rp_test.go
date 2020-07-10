// +build go1.13

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package armcore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/internal/mock"
)

const rpUnregisteredResp = `{
	"error":{
		"code":"MissingSubscriptionRegistration",
		"message":"The subscription registration is in 'Unregistered' state. The subscription must be registered to use namespace 'Microsoft.Storage'. See https://aka.ms/rps-not-found for how to register subscriptions.",
		"details":[{
				"code":"MissingSubscriptionRegistration",
				"target":"Microsoft.Storage",
				"message":"The subscription registration is in 'Unregistered' state. The subscription must be registered to use namespace 'Microsoft.Storage'. See https://aka.ms/rps-not-found for how to register subscriptions."
			}
		]
	}
}`

// some content was omitted here as it's not relevant
const rpRegisteringResp = `{
    "id": "/subscriptions/6d3860f6-8a11-431d-b3fa-1b3c4a8b888a/providers/Microsoft.Storage",
    "namespace": "Microsoft.Storage",
    "registrationState": "Registering",
    "registrationPolicy": "RegistrationRequired"
}`

// some content was omitted here as it's not relevant
const rpRegisteredResp = `{
    "id": "/subscriptions/6d3860f6-8a11-431d-b3fa-1b3c4a8b888a/providers/Microsoft.Storage",
    "namespace": "Microsoft.Storage",
    "registrationState": "Registered",
    "registrationPolicy": "RegistrationRequired"
}`

const requestEndpoint = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/fakeResourceGroupo/providers/Microsoft.Storage/storageAccounts/fakeAccountName"

func testRPRegistrationOptions(t azcore.Transport) *RegistrationOptions {
	def := DefaultRegistrationOptions()
	def.HTTPClient = t
	def.PollingDelay = 100 * time.Millisecond
	def.PollingDuration = 1 * time.Second
	return &def
}

func TestRPRegistrationPolicySuccess(t *testing.T) {
	srv, close := mock.NewServer()
	defer close()
	// initial response that RP is unregistered
	srv.AppendResponse(mock.WithStatusCode(http.StatusConflict), mock.WithBody([]byte(rpUnregisteredResp)))
	// polling responses to Register() and Get(), in progress
	srv.RepeatResponse(5, mock.WithStatusCode(http.StatusOK), mock.WithBody([]byte(rpRegisteringResp)))
	// polling response, successful registration
	srv.AppendResponse(mock.WithStatusCode(http.StatusOK), mock.WithBody([]byte(rpRegisteredResp)))
	// response for original request (different status code than any of the other responses)
	srv.AppendResponse(mock.WithStatusCode(http.StatusAccepted))
	pl := azcore.NewPipeline(srv, NewRPRegistrationPolicy(azcore.AnonymousCredential(), testRPRegistrationOptions(srv)))
	u1 := srv.URL()
	u2 := &u1
	u2, err := u2.Parse(requestEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	req := azcore.NewRequest(http.MethodGet, *u2)
	// log only RP registration
	azcore.Log().SetClassifications(LogRPRegistration)
	defer func() {
		// reset logging
		azcore.Log().SetClassifications()
	}()
	logEntries := 0
	azcore.Log().SetListener(func(cls azcore.LogClassification, msg string) {
		logEntries++
	})
	resp, err := pl.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected status code %d:", resp.StatusCode)
	}
	if resp.Request.URL.Path != requestEndpoint {
		t.Fatalf("unexpected path in response %s", resp.Request.URL.Path)
	}
	// should be three entries
	// 1st is for start
	// 2nd is for first response to get state
	// 3rd is when state transitions to success
	if logEntries != 3 {
		t.Fatalf("expected 3 log entries, got %d", logEntries)
	}
}

func TestRPRegistrationPolicyNA(t *testing.T) {
	srv, close := mock.NewServer()
	defer close()
	// response indicates no RP registration is required, policy does nothing
	srv.AppendResponse(mock.WithStatusCode(http.StatusOK))
	pl := azcore.NewPipeline(srv, NewRPRegistrationPolicy(azcore.AnonymousCredential(), testRPRegistrationOptions(srv)))
	req := azcore.NewRequest(http.MethodGet, srv.URL())
	// log only RP registration
	azcore.Log().SetClassifications(LogRPRegistration)
	defer func() {
		// reset logging
		azcore.Log().SetClassifications()
	}()
	azcore.Log().SetListener(func(cls azcore.LogClassification, msg string) {
		t.Fatalf("unexpected log entry %s: %s", cls, msg)
	})
	resp, err := pl.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}
}

func TestRPRegistrationPolicy409Other(t *testing.T) {
	const failedResp = `{
		"error":{
			"code":"CannotDoTheThing",
			"message":"Something failed in your API call.",
			"details":[{
					"code":"ThisIsForTesting",
					"message":"This is fake."
				}
			]
		}
	}`
	srv, close := mock.NewServer()
	defer close()
	// test getting a 409 but not due to registration required
	srv.AppendResponse(mock.WithStatusCode(http.StatusConflict), mock.WithBody([]byte(failedResp)))
	pl := azcore.NewPipeline(srv, NewRPRegistrationPolicy(azcore.AnonymousCredential(), testRPRegistrationOptions(srv)))
	req := azcore.NewRequest(http.MethodGet, srv.URL())
	// log only RP registration
	azcore.Log().SetClassifications(LogRPRegistration)
	defer func() {
		// reset logging
		azcore.Log().SetClassifications()
	}()
	azcore.Log().SetListener(func(cls azcore.LogClassification, msg string) {
		t.Fatalf("unexpected log entry %s: %s", cls, msg)
	})
	resp, err := pl.Do(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}
}

func TestRPRegistrationPolicyTimesOut(t *testing.T) {
	srv, close := mock.NewServer()
	defer close()
	// initial response that RP is unregistered
	srv.AppendResponse(mock.WithStatusCode(http.StatusConflict), mock.WithBody([]byte(rpUnregisteredResp)))
	// polling responses to Register() and Get(), in progress but slow
	// tests registration takes too long, times out
	srv.RepeatResponse(10, mock.WithStatusCode(http.StatusOK), mock.WithBody([]byte(rpRegisteringResp)), mock.WithSlowResponse(400*time.Millisecond))
	pl := azcore.NewPipeline(srv, NewRPRegistrationPolicy(azcore.AnonymousCredential(), testRPRegistrationOptions(srv)))
	u1 := srv.URL()
	u2 := &u1
	u2, err := u2.Parse(requestEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	req := azcore.NewRequest(http.MethodGet, *u2)
	// log only RP registration
	azcore.Log().SetClassifications(LogRPRegistration)
	defer func() {
		// reset logging
		azcore.Log().SetClassifications()
	}()
	logEntries := 0
	azcore.Log().SetListener(func(cls azcore.LogClassification, msg string) {
		logEntries++
	})
	resp, err := pl.Do(context.Background(), req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	// should be two entries
	// 1st is for start
	// 2nd is for first response to get state
	if logEntries != 2 {
		t.Fatalf("expected 2 log entries, got %d", logEntries)
	}
	// we should get the response from the original request
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}
}

func TestRPRegistrationPolicyExceedsAttempts(t *testing.T) {
	srv, close := mock.NewServer()
	defer close()
	// add a cycle of unregistered->registered so that we keep retrying and hit the cap
	for i := 0; i < 4; i++ {
		// initial response that RP is unregistered
		srv.AppendResponse(mock.WithStatusCode(http.StatusConflict), mock.WithBody([]byte(rpUnregisteredResp)))
		// polling responses to Register() and Get(), in progress
		srv.RepeatResponse(2, mock.WithStatusCode(http.StatusOK), mock.WithBody([]byte(rpRegisteringResp)))
		// polling response, successful registration
		srv.AppendResponse(mock.WithStatusCode(http.StatusOK), mock.WithBody([]byte(rpRegisteredResp)))
	}
	pl := azcore.NewPipeline(srv, NewRPRegistrationPolicy(azcore.AnonymousCredential(), testRPRegistrationOptions(srv)))
	u1 := srv.URL()
	u2 := &u1
	u2, err := u2.Parse(requestEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	req := azcore.NewRequest(http.MethodGet, *u2)
	// log only RP registration
	azcore.Log().SetClassifications(LogRPRegistration)
	defer func() {
		// reset logging
		azcore.Log().SetClassifications()
	}()
	logEntries := 0
	azcore.Log().SetListener(func(cls azcore.LogClassification, msg string) {
		logEntries++
	})
	resp, err := pl.Do(context.Background(), req)
	if err == nil {
		t.Fatal("unexpected nil error")
	}
	if !strings.HasPrefix(err.Error(), "exceeded attempts to register Microsoft.Storage") {
		t.Fatalf("unexpected error message %s", err.Error())
	}
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("unexpected status code %d:", resp.StatusCode)
	}
	if resp.Request.URL.Path != requestEndpoint {
		t.Fatalf("unexpected path in response %s", resp.Request.URL.Path)
	}
	// should be 3 entries for each attempt, total 9 entries
	// 1st is for start
	// 2nd is for first response to get state
	// 3rd is when state transitions to success
	if logEntries != 9 {
		t.Fatalf("expected 9 log entries, got %d", logEntries)
	}
}

// test cancelling registration
func TestRPRegistrationPolicyCanCancel(t *testing.T) {
	srv, close := mock.NewServer()
	defer close()
	// initial response that RP is unregistered
	srv.AppendResponse(mock.WithStatusCode(http.StatusConflict), mock.WithBody([]byte(rpUnregisteredResp)))
	// polling responses to Register() and Get(), in progress but slow so we have time to cancel
	srv.RepeatResponse(10, mock.WithStatusCode(http.StatusOK), mock.WithBody([]byte(rpRegisteringResp)), mock.WithSlowResponse(300*time.Millisecond))
	opts := DefaultRegistrationOptions()
	opts.HTTPClient = srv
	pl := azcore.NewPipeline(srv, NewRPRegistrationPolicy(azcore.AnonymousCredential(), &opts))
	// log only RP registration
	azcore.Log().SetClassifications(LogRPRegistration)
	defer func() {
		// reset logging
		azcore.Log().SetClassifications()
	}()
	logEntries := 0
	azcore.Log().SetListener(func(cls azcore.LogClassification, msg string) {
		logEntries++
	})
	u1 := srv.URL()
	u2 := &u1
	u2, err := u2.Parse(requestEndpoint)
	if err != nil {
		t.Fatal(err)
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)

	ctx, cancel := context.WithCancel(context.Background())
	var resp *azcore.Response
	go func() {
		// create request and start pipeline
		req := azcore.NewRequest(http.MethodGet, *u2)
		resp, err = pl.Do(ctx, req)
		wg.Done()
	}()

	// wait for a bit then cancel the operation
	time.Sleep(500 * time.Millisecond)
	cancel()
	wg.Wait()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected Canceled error, got %v", err)
	}
	// there should be 1 or 2 entries depending on the timing
	if logEntries == 0 {
		t.Fatal("didn't get any log entries")
	}
	// should have original response
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("unexpected status code %d", resp.StatusCode)
	}
}
