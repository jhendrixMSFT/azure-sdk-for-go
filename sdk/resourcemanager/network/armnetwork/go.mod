module github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork

go 1.16

require (
	github.com/Azure/azure-sdk-for-go v59.0.0+incompatible
	github.com/Azure/azure-sdk-for-go/sdk/azcore/v2 v2.0.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v0.12.0
)

replace github.com/Azure/azure-sdk-for-go/sdk/azcore/v2 => github.com/jhendrixMSFT/azure-sdk-for-go/sdk/azcore/v2 v2.0.0-20211110162616-323d9aebe946

replace github.com/Azure/azure-sdk-for-go/sdk/azidentity => github.com/jhendrixMSFT/azure-sdk-for-go/sdk/azidentity v0.0.0-20211110164513-f6c1c9b01095
