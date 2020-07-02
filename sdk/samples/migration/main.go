package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/arm/compute/2019-12-01/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-12-01/compute"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
)

func main() {

}

var authorizer autorest.Authorizer // track 1 credential, value obtained from auth
var credential azcore.Credential   // track 2 credential, value obtained from azidentity

// example for authentication
func Authentication() {
	// Track 1 create authorizer from environment vars
	authorizer, _ = auth.NewAuthorizerFromEnvironment()

	// Track 2 equivalent
	credential, _ = azidentity.NewEnvironmentCredential(nil)
}

// example for creating a compute VM client
func CreateComputeClient() {
	// Track 1 create compute VM client
	vmClient := compute.NewVirtualMachinesClient("subscription ID")
	vmClient.Authorizer = authorizer

	// Track 2 equivalent
	client, _ := armcompute.NewDefaultClient(credential, nil)
	// client contains methods to access all operation groups
	client.VirtualMachinesOperations("subscription ID")
}

// waiting for an LRO to complete
func LROExample1() {
	// Track 1 wait for an LRO to complete
	track1Client := compute.NewVirtualMachinesClient("subscription ID")
	track1Client.Authorizer = authorizer
	future, _ := track1Client.CreateOrUpdate(context.Background(), "resource_group", "vm_name", compute.VirtualMachine{})
	future.WaitForCompletionRef(context.Background(), track1Client.Client)

	// Track 2 equivalent
	track2Client, _ := armcompute.NewDefaultClient(credential, nil)
	vmOps := track2Client.VirtualMachinesOperations("subscription ID")
	response, _ := vmOps.BeginCreateOrUpdate(context.Background(), "resource_group", "vm_name", armcompute.VirtualMachine{})
	response.PollUntilDone(context.Background(), 10*time.Second) // polling interval used in lieu of Retry-After header
}

// custom polling on an LRO
func LROExample2() {
	// Track 1 wait for an LRO to complete
	track1Client := compute.NewVirtualMachinesClient("subscription ID")
	track1Client.Authorizer = authorizer
	future, _ := track1Client.CreateOrUpdate(context.Background(), "resource_group", "vm_name", compute.VirtualMachine{})
	done := false
	for !done {
		// do custom stuff here
		done, _ = future.DoneWithContext(context.Background(), track1Client.Client)
	}

	// Track 2 equivalent
	track2Client, _ := armcompute.NewDefaultClient(credential, nil)
	vmOps := track2Client.VirtualMachinesOperations("subscription ID")
	response, _ := vmOps.BeginCreateOrUpdate(context.Background(), "resource_group", "vm_name", armcompute.VirtualMachine{})
	for !response.Poller.Done() {
		// do custom stuff here
		response.Poller.Poll(context.Background())
	}
}

// interating over paged responses
func PageableResponses() {
	// Track 1 iterate over pages
	track1Client := compute.NewVirtualMachinesClient("subscription ID")
	track1Client.Authorizer = authorizer
	for page, err := track1Client.List(context.Background(), "resource_group"); page.NotDone(); err = page.Next() {
		if err != nil {
			panic(err)
		}
		for _, v := range page.Values() {
			fmt.Println(*v.Name)
		}
	}

	// Track 2 equivalent
	track2Client, _ := armcompute.NewDefaultClient(credential, nil)
	vmOps := track2Client.VirtualMachinesOperations("subscription ID")
	vmPager, _ := vmOps.List("resource_group")
	for vmPager.NextPage(context.Background()) {
		resp := vmPager.PageResponse()
		for _, vm := range *resp.VirtualMachineListResult.Value {
			fmt.Println(*vm.Name)
		}
	}
	if vmPager.Err() != nil {
		panic(vmPager.Err())
	}
}
