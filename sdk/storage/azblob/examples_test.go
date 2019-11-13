// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azblob

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

const (
	endpoint = "https://<endpoint>.blob.core.windows.net/"
)

const (
	tenantID     = "<tenant>"
	clientID     = "<client>"
	clientSecret = "<secret>"
)

const (
	accountName = "<storageaccount>"
	accountKey  = "<accountkey>"
)

func clientSecretCredential() azcore.TokenCredential {
	secret, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		panic(err)
	}
	return secret
}

func ExampleAnonymousCredential() {
	client, err := NewServiceClient(endpoint,
		AnonymousCredential(),
		azcore.PipelineOptions{})
	if err != nil {
		panic(err)
	}
	iter := client.ListContainers(nil)
	for iter.NextItem(context.Background()) {
		fmt.Println(iter.Item().Name)
	}
	if iter.Err() != nil {
		panic(iter.Err())
	}
}

func ExampleSharedKeyCredential() {
	client, err := NewServiceClient(endpoint,
		SharedKeyCredential(accountName, accountKey),
		azcore.PipelineOptions{})
	if err != nil {
		panic(err)
	}
	iter := client.ListContainers(nil)
	for iter.NextItem(context.Background()) {
		fmt.Println(iter.Item().Name)
	}
	if iter.Err() != nil {
		panic(iter.Err())
	}
}

func ExampleTokenCredential() {
	client, err := NewServiceClient(endpoint,
		TokenCredential(clientSecretCredential()),
		azcore.PipelineOptions{})
	if err != nil {
		panic(err)
	}
	iter := client.ListContainers(nil)
	for iter.NextItem(context.Background()) {
		fmt.Println(iter.Item().Name)
	}
	if iter.Err() != nil {
		panic(iter.Err())
	}
}
