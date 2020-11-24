# gatewayapi (deprecated)

This pkg used to provide the handler for Lambda functions which served as a Lambda-proxy backend to API gateway.

Those internal gateways have all been removed, so this pkg now just contains a `Client` that makes
it easy to talk to those old Lambda handlers directly:

- `panther-analysis-api`
- `panther-compliance-api`
- `panther-remediation-api`
- `panther-resources-api`

```go
package main

import (
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/lambda"

    "github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

// Example usage
func main() {
    awsSession := session.Must(session.NewSession())
    client := gatewayapi.NewClient(lambda.New(awsSession), "panther-analysis-api")

    input := models.LambdaInput{ListRules: &models.ListRulesInput{}}
    var output models.ListRulesOutput
    statusCode, err := client.Invoke(&input, &output)
}
```

Once the internal API has been consolidated, this package will no longer be necessary.

Do not use this pkg for any new code.
