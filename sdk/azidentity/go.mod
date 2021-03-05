module github.com/Azure/azure-sdk-for-go/sdk/azidentity

go 1.14

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v0.14.0
	github.com/Azure/azure-sdk-for-go/sdk/internal v0.5.0
	github.com/AzureAD/microsoft-authentication-library-for-go v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
)

replace github.com/AzureAD/microsoft-authentication-library-for-go => ../../../../AzureAD/microsoft-authentication-library-for-go
