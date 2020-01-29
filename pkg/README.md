# Exported Panther Packages

Standalone go utilities shared by multiple projects. See each module for details:

- [`awsbatch`](awsbatch) - backoff/paging/retry for AWS batch operations
- [`awsglue`](awsglue) - abstractions and utilities for AWS Glue operations
- [`extract`](extract) - utility using gjson to walk parse tree to extract elements
- [`gatewayapi`](gatewayapi) - utilities for developing Gateway API Lambda proxies
- [`genericapi`](genericapi) - _DEPRECATED_ - provides router for API-style Lambda functions
- [`lambdalogger`](lambdalogger) - installs global zap logger with lambda request ID
- [`oplog`](oplog) - standardized logging for operations (events with start/stop/status)
- [`testutils`](testutils) - helper functions for integration tests
