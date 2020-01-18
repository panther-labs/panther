## testutils
This provides some convenience methods for writing integration tests.

## Functions
* `ClearDynamoTable(awsSession, tableName string)` - Delete all items in a DynamoDB table
* `ClearS3Bucket(awsSession, bucketName string)` - Delete all object versions in an S3 bucket

## Example Integration Test

```go
package main

import (
    "flag"
    "os"
    "testing"

    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/stretchr/testify/require"

    "github.com/panther-labs/panther/pkg/testutils"
)

var (
    awsSession      = session.Must(session.NewSession())
    integrationFlag = flag.Bool("integration", false, "run integration tests")
)

func TestMain(m *testing.M) {
    flag.Parse()
    os.Exit(m.Run())
}

func TestIntegrationAPI(t *testing.T) {
    if !*integrationFlag {
        t.Skip()
    }

    // Reset backend state - erase dynamo table and S3 bucket
    require.NoError(t, testutils.ClearDynamoTable(awsSession, "panther-rules-table"))
    require.NoError(t, testutils.ClearS3Bucket(awsSession, "panther-rules-bucket"))
}
```
