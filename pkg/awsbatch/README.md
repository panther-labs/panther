# awsbatch
AWS batch operations with input paging, backoff, and retry for failed items.

When reading or writing items in bulk to an AWS service, the caller typically has to worry about:
* **Maximum request size:** There is an upper bound on the number of items in each request
* **Retrying failed items:** In each batch operation, a subset of items can fail
* **Backoff:** There needs to be exponential backoff if a request fails

Inspired by Python's super-simple [batch writer](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/dynamodb.html#batch-writing), this library takes care of all of those concerns.
The caller simply provides the AWS input as usual, and `awsbatch` handles the rest.

## Functions
* `dynamodbbatch.BatchGetItem`
* `dynamodbbatch.BatchWriteItem`
* `kinesisbatch.PutRecords`
* `s3batch.DeleteObjects`
* `sqsbatch.SendMessageBatch`

## Example Usage
```go
package main

import (
    "time"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/kinesis"

    "github.com/panther-labs/panther/pkg/awsbatch/kinesisbatch"
)

func main() {
    // Build the PutRecordsInput like normal
    input := &kinesis.PutRecordsInput{
        Records:    make([]*kinesis.PutRecordsRequestEntry, 10000),
        StreamName: aws.String("kinesis-stream-name"),
    }

    // Add as many records as needed
    for i := 0; i < 10000; i++ {
        input.Records[i] = &kinesis.PutRecordsRequestEntry{
            Data: []byte("{\"key\": 123}"),
            PartitionKey: aws.String("partition-key"),
        }
    }

    // Send the requests in multiple batches with backoff and retry
    client := kinesis.New(session.Must(session.NewSession()))
    maxBackoff := 30 * time.Second
    if err := kinesisbatch.PutRecords(client, maxBackoff, input); err != nil {
        // Kinesis exception, backoff timeout, or unable to process all items
        panic(err)
    }
}
```

The setup is very similar for the other batch functions.
