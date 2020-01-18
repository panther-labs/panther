# genericapi
Provides common logic for Lambda functions which serve as a Lambda-proxy backend to API Gateway:

* `LambdaProxy` to generate the main Lambda handler
* `GatewayClient` for building an HTTP client that can sign requests for AWS_IAM authentication
* `MarshalResponse` for serializing an API response model
    * `ReplaceMapSliceNils` for recursively replacing nil slices and maps with initialized versions

## Example API Handler

```go
package main

import (
	"context"
	
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var methodHandlers = map[string]gatewayapi.RequestHandler {
	"GET /orgs/{orgId}": getOrganization,
}

func getOrganization(request *events.APIGatewayProxyRequest) *events.APIGatewayProxyResponse {
	// The request contains the http method, path, path parameters, query parameters, body, etc.
	orgId := models.OrgID(request.PathParameters["orgId"])
	sortAscending := request.QueryStringParameters["asc"]
	
	// models is the auto-generated package from swagger
	result := &models.ListOrganizationsResponse{}
	return gatewayapi.MarshalResponse(result)
}

func main() {
	lambda.Start(gatewayapi.LambdaProxy(methodHandlers))
}
```

## Example Invocation
```go
package main

import (
	"github.com/aws/aws-sdk-go/aws/session"
	
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

var (
	awsSession = session.Must(session.NewSession())
	httpClient = gatewayapi.GatewayClient(awsSession)
)

func main() {
	// client is the auto-generated package from swagger
	config := client.DefaultTransportConfig().
		WithBasePath("/v1").
		WithHost("l4ekvgdy92.execute-api.us-west-2.amazonaws.com")  // replace with your endpoint
	apiclient := client.NewHTTPClientWithConfig(nil, config)
	
	result, err := apiclient.Operations.ListOrganizations(
		&operations.AddResourceParams{
			// ...
			HTTPClient: httpClient,
		})
}
```
