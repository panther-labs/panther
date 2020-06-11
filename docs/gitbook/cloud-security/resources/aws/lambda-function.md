# Lambda Function

#### Resource Type

`AWS.Lambda.Function`

#### Resource ID Format

For Lambda Functions, the resource ID is the ARN.

`arn:aws:lambda:us-west-2:123456789012:function:example-function`

#### Background

AWS Lambda is a compute service that lets you run code without provisioning or managing servers.

#### Fields

| Field         | Type     | Description                                                                                                        |
| :------------ | :------- | :----------------------------------------------------------------------------------------------------------------- |
| `Policy`      | `Map`    | A mapping with `Policy` \(the resource-based policy\) and `RevisionId` \(the current revision of the policy\) keys |
| `Environment` | `Map`    | The environment variables and error state of the function                                                          |
| `Runtime`     | `String` | The runtime environment of the function, such as `go1.x` or `python3.x`                                            |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:lambda:us-west-2:123456789012:function:example-function",
    "CodeSha256": "1234=",
    "CodeSize": 10000,
    "DeadLetterConfig": null,
    "Description": "This is an example lambda function",
    "Environment": {
        "Error": null,
        "Variables": {
            "DEBUG": "False",
            "VAR1": "Var1Value"
        }
    },
    "Handler": "handler",
    "KMSKeyArn": null,
    "LastModified": "2019-01-01T00:00:00.000+0000",
    "Layers": null,
    "MasterArn": null,
    "MemorySize": 256,
    "Name": "example-function",
    "Policy": {
        "Policy": "{\"Policy\": \"{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"sns\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:us-west-2:123456789012:function:example-function\"}]}",
        "RevisionId": "abcdefg-1234567890-abcdefg"
    },
    "Region": "us-west-2",
    "ResourceId": "arn:aws:lambda:us-west-2:123456789012:function:example-function",
    "ResourceType": "AWS.Lambda.Function",
    "RevisionId": "1",
    "Role": "arn:aws:iam::123456789012:role/example-function-role",
    "Runtime": "go1.x",
    "Tags": {
        "Key1": "Value1",
        "Key2": "Value2"
    },
    "TimeCreated": null,
    "Timeout": 60,
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "Version": "$LATEST",
    "VpcConfig": null
}
```
