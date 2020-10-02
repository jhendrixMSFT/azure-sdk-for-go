module github.com/Azure/azure-sdk-for-go/service

go 1.13

require (
	github.com/Azure/azure-sdk-for-go/sdk/arm/appconfiguration/2019-10-01/armappconfiguration v0.1.0
	github.com/Azure/azure-sdk-for-go/sdk/arm/compute/2019-12-01/armcompute v0.1.0
	github.com/Azure/azure-sdk-for-go/sdk/azcore v0.10.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/blob/2019-07-07/azblob v0.1.0
)

replace (
	github.com/Azure/azure-sdk-for-go/sdk/arm/appconfiguration/2019-10-01/armappconfiguration => ../sdk/arm/appconfiguration/2019-10-01/armappconfiguration
	github.com/Azure/azure-sdk-for-go/sdk/arm/compute/2019-12-01/armcompute => ../sdk/arm/compute/2019-12-01/armcompute
	github.com/Azure/azure-sdk-for-go/sdk/storage/blob/2019-07-07/azblob => ../sdk/storage/blob/2019-07-07/azblob
)
