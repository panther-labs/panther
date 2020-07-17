# Writing a New Parser

To add support for a new log type, write a custom **Parser**, which controls how Panther converts raw strings into parsed events for analysis by the rules engine.

Follow the developer guide below to write a new Parser.

## Getting Started

Each parser must be created inside of the [parsers](https://github.com/panther-labs/panther/tree/master/internal/log_analysis/log_processor/parsers) folder.

- If it belongs to an existing family of parsers (e.g. aws, osquery) add the parser to the existing package
- If not, create a new package and place the parser within

## Developing

Parsers represent logs as Go [structs](https://tour.golang.org/moretypes/2) and contain methods to load log fields into these structs. Parsers also perform normalization logic to populate the [Panther fields](../panther-fields.md) for incident response and investigations.

{% hint style="info" %}
Use the [CloudTrail parser](https://github.com/panther-labs/panther/blob/master/internal/log_analysis/log_processor/parsers/awslogs/cloudtrail.go) as an example.
{% endhint %}

### Fields

The first step is to express the structure of the log as structs. The online tool [JSON-to-Go](https://mholt.github.io/json-to-go/) can help facilitate the creation of the initial structure.

Take the following example (factitious) IDS log:

```json
{
  "time": "2018-08-26T14:17:23Z",
  "user_uuid": "e5f06532-31ef-474c-b70b-ef4c017bd021",
  "hostname": "web-01.prod.acme.co",
  "details": {
    "name": "suspicious command found",
    "command": "sudo nc -l -p 3364",
    "score": 9.8
  },
  "context": {
    "parameters": "-l -p 3364",
    "command": "nc"
  }
}
```

To express this as a set of structs:

```go
package examplelogs

import (
	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type ExampleLog struct {
	Time     *timestamp.RFC3339   `json:"time,omitempty" description:"The time of the IDS alert"`
	UserUUID *string              `json:"user_uuid,omitempty" validate:"required" description:"The user who executed the command"`
	Hostname *string              `json:"hostname,omitempty" validate:"required" description:"The hostname where the log came from"`
	Details  *ExampleLogDetails   `json:"details,omitempty" validate:"required" description:"Metadata about the alert"`
	Context  *jsoniter.RawMessage `json:"context,omitempty" description:"Contextual information about the alert"`
}

type ExampleLogDetails struct {
	Name    *string  `json:"name,omitempty" description:"The name of the IDS alert"`
	Command *string  `json:"command" description:"The command executed on the host"`
	Score   *float64 `json:"score" description:""`
}
```

#### Tips

1. Use the `validate` tag as appropriate to represent the expected field values. If the field is mandatory, mark is as `validate:"required"`.
1. Always include a `description` tag with a short summary of each field which is viewable in the Panther documentation and Data Explorer.
1. Pick the right [datatype](https://tour.golang.org/basics/11) for each field and make sure it's a pointer. For numbers, use specific-length types (like `int32` versus `int`). Use `uintX` types only when it makes sense for the value of the field (like `ports`).
1. Express time fields as `*timestamp.RFC3339`.
1. When parsing dynamic fields, such as request or response parameters, use the `*jsoniter.RawMessage` type.

{% hint style="info" %}
For more information on the `validate` functionality, check out the [godoc](https://godoc.org/gopkg.in/go-playground/validator.v9).
{% endhint %}

### Methods

The Parser must include the following methods:

- [New()](https://github.com/panther-labs/panther/blob/master/internal/log_analysis/log_processor/parsers/awslogs/cloudtrail.go#L122): Instantiates the Parser
- [Parse()](https://github.com/panther-labs/panther/blob/master/internal/log_analysis/log_processor/parsers/awslogs/cloudtrail.go#L127): Unmarshalling, validating, and extracting the Panther fields
- [LogType()](https://github.com/panther-labs/panther/blob/master/internal/log_analysis/log_processor/parsers/awslogs/cloudtrail.go#L151): Returns a string in the form of `Type.Subtype`

### Finalizing

To enable the new parser, import it in the [parser registry](https://github.com/panther-labs/panther/blob/master/internal/log_analysis/log_processor/registry/registry.go) and add it to the `LOG_TYPES` [constant](https://github.com/panther-labs/panther/blob/master/web/src/constants.ts) in the web frontend.

### Testing

The easiest way to test a new parser is by writing a set of unit tests with sample logs. This is recommended before deploying to Panther for testing.

Again, use the [CloudTrail Parser](https://github.com/panther-labs/panther/blob/master/internal/log_analysis/log_processor/parsers/awslogs/cloudtrail_test.go) as an example here.

### Before making a pull-request

* Ensure your code is formatted, run `mage fmt`
* Ensure all tests pass `mage test:ci`
* Be sure to checkin the documentation that will be automatically generated and update the [SUMMARY.md](https://github.com/panther-labs/panther/blob/master/docs/gitbook/SUMMARY.md) if you added a new family of log.
* Deploy Panther. You should be able to see a new table with your added parser in Glue Data Catalog
* Do an end-to-end test. You can use [s3queue](../../operations/ops-home.md#tools) to copy test files into the `panther-bootstrap-auditlogs-<id>` bucket to drive log processing or use the development tool `./out/bin/devtools/<os>/<arch>/logprocessor` to read files from the local file system.
* Write a test rule for the new type to ensure data is flowing.
