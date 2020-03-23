# Nginx Logs

[Nginx](https://www.nginx.com/) is a powerful open source web server. Nginx log formats are configurable, and Panther supports the NCSA combined log format for access logs.

| Log Type       | Reference                                              |
| -------------- | ------------------------------------------------------ |
| `Nginx.Access` | http://nginx.org/en/docs/http/ngx_http_log_module.html |

## Nginx.Access

```json
{
    "remoteAddr": {
        "type": "string"
    },
    "remoteUser": {
        "type": "string"
    },
    "time": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "request": {
        "type": "string"
    },
    "status": {
        "type": "integer"
    },
    "bodyBytesSent": {
        "type": "integer"
    },
    "httpReferer": {
        "type": "string"
    },
    "httpUserAgent": {
        "type": "string"
    },
    "p_log_type": {
        "type": "string"
    },
    "p_row_id": {
        "type": "string"
    },
    "p_event_time": {
        "$ref": "#/definitions/RFC3339"
    },
    "p_parse_time": {
        "$ref": "#/definitions/RFC3339"
    },
    "p_any_ip_addresses": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_domain_names": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_sha1_hashes": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_md5_hashes": {
        "$ref": "#/definitions/PantherAnyString"
    }
}
```
