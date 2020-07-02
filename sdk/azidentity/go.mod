module github.com/Azure/azure-sdk-for-go/sdk/azidentity

go 1.13

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v0.8.0
	github.com/Azure/azure-sdk-for-go/sdk/internal v0.1.0
)

replace github.com/Azure/azure-sdk-for-go/sdk/azcore => ../azcore

replace github.com/Azure/azure-sdk-for-go/sdk/internal => ../internal
