# Syslogs

[Syslog](https://en.wikipedia.org/wiki/Syslog) is a protocol for message logging. It has become the standard logging solution on Unix-like systems.

| Log Type          | Reference                                              |
| ----------------- | ------------------------------------------------------ |
| `Syslog.RFC3164`  | https://tools.ietf.org/html/rfc3164                    |
| `Syslog.RFC5424`  | https://tools.ietf.org/html/rfc5424                    |


## Syslog.RFC3164

```json
{
    "priority": {
        "type": "integer"
    },
    "facility": {
        "type": "integer"
    },
    "severity": {
        "type": "integer"
    },
    "timestamp": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "hostname": {
        "type": "string"
    },
    "appname": {
        "type": "string"
    },
    "procid": {
        "type": "string"
    },
    "msgid": {
        "type": "string"
    },
    "message": {
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

## Syslog.RFC5424

```json
{
    "priority": {
        "type": "integer"
    },
    "facility": {
        "type": "integer"
    },
    "severity": {
        "type": "integer"
    },
    "version": {
        "type": "integer"
    },
    "timestamp": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "hostname": {
        "type": "string"
    },
    "appname": {
        "type": "string"
    },
    "procid": {
        "type": "string"
    },
    "msgid": {
        "type": "string"
    },
    "structured_data": {
        "patternProperties": {
            ".*": {
                "patternProperties": {
                    ".*": {
                        "type": "string"
                    }
                },
                "type": "object"
            }
        },
        "type": "object"
    },
    "message": {
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
