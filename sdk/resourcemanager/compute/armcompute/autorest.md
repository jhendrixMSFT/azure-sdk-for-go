### AutoRest Configuration

> see https://aka.ms/autorest

``` yaml
azure-arm: true
generate-fakes: true
modelerfour:
  lenient-model-deduplication: true
require:
- https://github.com/Azure/azure-rest-api-specs/blob/e7bf3adfa2d5e5cdbb804eec35279501794f461c/specification/compute/resource-manager/readme.md
- https://github.com/Azure/azure-rest-api-specs/blob/e7bf3adfa2d5e5cdbb804eec35279501794f461c/specification/compute/resource-manager/readme.go.md
license-header: MICROSOFT_MIT_NO_VERSION
module: github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v4
module-version: 4.1.0
output-folder: $(go-sdk-folder)/sdk/resourcemanager/compute/armcompute
```
