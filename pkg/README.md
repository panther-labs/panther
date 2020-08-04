# Exported Panther Packages

Standalone go utilities shared by multiple projects. See each module for details:

- [`awsathena`](awsathena) - query support and utilities for using AWS Athena
- [`awsbatch`](awsbatch) - backoff/paging/retry for AWS batch operations
- [`awscfn`](awscfn) - helpers that query/manipulate AWS Cloudformation stacks
- [`awsretry`](retry) - helper that wraps the AWS retryer interface for cases not handled by SDK
- [`awssqs`](awssqs) - wrappers for commmon sqs patterns
- [`box`](box) - boxing helpers
- [`encryption`](encryption) - encryption helpers
- [`extract`](extract) - utility using gjson to walk parse tree to extract elements
- [`gatewayapi`](gatewayapi) - utilities for developing Gateway API Lambda proxies
- [`genericapi`](genericapi) - provides router for API-style Lambda functions
- [`lambdalogger`](lambdalogger) - installs global zap logger with lambda request ID
- [`mertics`](metrics) - helpers to use the AWS embedded metric format
- [`oplog`](oplog) - standardized logging for operations (events with start/stop/status)
- [`shutil`](shutil) - FIXME: likely should be renamed to ziputil
- [`prompt`](prompt) - util functions to read user input from terminal
- [`testutils`](testutils) - helper functions for integration tests
- [`unbox`](unbox) - un-boxing helpers
