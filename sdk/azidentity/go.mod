module github.com/Azure/azure-sdk-for-go/sdk/azidentity

go 1.16

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore/v2 v2.0.0
	github.com/Azure/azure-sdk-for-go/sdk/internal v0.8.1
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pkg/browser v0.0.0-20180916011732-0a3d74bf9ce4
	golang.org/x/crypto v0.0.0-20201016220609-9e8e0b390897
	golang.org/x/net v0.0.0-20210610132358-84b48f89b13b
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace github.com/Azure/azure-sdk-for-go/sdk/azcore/v2 => github.com/jhendrixMSFT/azure-sdk-for-go/sdk/azcore/v2 v2.0.0-20211110162616-323d9aebe946
