# lambdalogger

Initialize a zap logger for your Lambda function with the request ID and other initial fields.

This makes it possible to easily search for logs from a given invocation and is required for all
Panther Go Lambda functions.

## Example Usage

```go
package main

import (
    "context"

    "github.com/aws/aws-lambda-go/lambda"
    "go.uber.org/zap"

    "github.com/panther-labs/panther/pkg/lambdalogger"
)

func lambdaHandler(ctx context.Context, event interface{}) {
    // Configure the global zap logger.
    // DEBUG mode is used if strings.lower(os.Getenv("DEBUG")) == "true".
    lambdaContext, logger := lambdalogger.ConfigureGlobal(ctx, nil)

    // The returned logger is the same as the global zap logger: zap.L()
    // The global zap logger can now be called from anywhere in the source code.
    logger.Info("function invoked", zap.Any("event", event))
    zap.L().Info("another way to log", zap.String("arn", lambdaContext.InvokedFunctionArn))
}

func main() {
    lambda.Start(lambdaHandler)
}
```
