module migration

go 1.14

require (
	github.com/Azure/azure-sdk-for-go v43.2.0+incompatible
	github.com/Azure/azure-sdk-for-go/sdk/arm/compute/2019-12-01/armcompute v0.0.0-00010101000000-000000000000
	github.com/Azure/azure-sdk-for-go/sdk/azcore v0.8.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v0.0.0-00010101000000-000000000000
	github.com/Azure/go-autorest/autorest v0.11.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.0
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.0 // indirect
)

replace (
	github.com/Azure/azure-sdk-for-go/sdk/arm/compute/2019-12-01/armcompute => ../../arm/compute/2019-12-01/armcompute
	github.com/Azure/azure-sdk-for-go/sdk/arm/network/2020-03-01/armnetwork => ../../arm/network/2020-03-01/armnetwork
	github.com/Azure/azure-sdk-for-go/sdk/azidentity => ../../azidentity
)
