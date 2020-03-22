# Osquery Logs

[Osquery](osquery.io) is an [open source tool](https://github.com/osquery/osquery) for SQL powered operating system instrumentation, monitoring, and analytics. It's helpful for collecting data such as installed users, applications, processes, files, system logs, and much more.

| Log Type               | Reference                                                                    |
| ---------------------- | ---------------------------------------------------------------------------- |
| `Osquery.Batch`        | https://osquery.readthedocs.io/en/stable/deployment/logging/#batch-format    |
| `Osquery.Differential` | https://osquery.readthedocs.io/en/stable/deployment/logging/#event-format    |
| `Osquery.Snapshot`     | https://osquery.readthedocs.io/en/stable/deployment/logging/#snapshot-format |
| `Osquery.Status`       | https://osquery.readthedocs.io/en/stable/deployment/logging/#status-logs     |

## Osquery.Batch

```json
{
    "calendarTime": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/ANSICwithTZ"
    },
    "counter": {
        "type": "integer"
    },
    "decorations": {
        "patternProperties": {
            ".*": {
                "type": "string"
            }
        },
        "type": "object"
    },
    "diffResults": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/BatchDiffResults"
    },
    "epoch": {
        "type": "integer"
    },
    "hostname": {
        "type": "string"
    },
    "name": {
        "type": "string"
    },
    "unixTime": {
        "type": "integer"
    },
    "p_log_type": {
        "type": "string"
    },
    "p_row_id": {
        "type": "string"
    },
    "p_event_time": {
        "$schema": "http://json-schema.org/draft-04/schema#",
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

### BatchDiffResults
```json
{
    "added": {
        "items": {
            "patternProperties": {
                ".*": {
                    "type": "string"
                }
            },
            "type": "object"
        },
        "type": "array"
    },
    "removed": {
        "items": {
            "patternProperties": {
                ".*": {
                    "type": "string"
                }
            },
            "type": "object"
        },
        "type": "array"
    }
}
```

## Osquery.Differential

```json
{
    "action": {
        "type": "string"
    },
    "calendarTime": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/ANSICwithTZ"
    },
    "columns": {
        "patternProperties": {
            ".*": {
                "type": "string"
            }
        },
        "type": "object"
    },
    "counter": {
        "type": "integer"
    },
    "decorations": {
        "patternProperties": {
            ".*": {
                "type": "string"
            }
        },
        "type": "object"
    },
    "epoch": {
        "type": "integer"
    },
    "hostIdentifier": {
        "type": "string"
    },
    "logType": {
        "type": "string"
    },
    "log_type": {
        "type": "string"
    },
    "name": {
        "type": "string"
    },
    "unixTime": {
        "type": "integer"
    },
    "logNumericsAsNumbers": {
        "type": "boolean"
    },
    "p_log_type": {
        "type": "string"
    },
    "p_row_id": {
        "type": "string"
    },
    "p_event_time": {
        "$schema": "http://json-schema.org/draft-04/schema#",
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

## Osquery.Status

```json
{
    "calendarTime": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/ANSICwithTZ"
    },
    "decorations": {
        "patternProperties": {
            ".*": {
                "type": "string"
            }
        },
        "type": "object"
    },
    "filename": {
        "type": "string"
    },
    "hostIdentifier": {
        "type": "string"
    },
    "line": {
        "type": "integer"
    },
    "logType": {
        "type": "string"
    },
    "log_type": {
        "type": "string"
    },
    "message": {
        "type": "string"
    },
    "severity": {
        "type": "integer"
    },
    "unixTime": {
        "type": "integer"
    },
    "version": {
        "type": "string"
    },
    "p_log_type": {
        "type": "string"
    },
    "p_row_id": {
        "type": "string"
    },
    "p_event_time": {
        "$schema": "http://json-schema.org/draft-04/schema#",
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

### Osquery.Snapshot

```json
{
    "action": {
        "type": "string"
    },
    "calendarTime": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/ANSICwithTZ"
    },
    "counter": {
        "type": "integer"
    },
    "decorations": {
        "patternProperties": {
            ".*": {
                "type": "string"
            }
        },
        "type": "object"
    },
    "epoch": {
        "type": "integer"
    },
    "hostIdentifier": {
        "type": "string"
    },
    "name": {
        "type": "string"
    },
    "snapshot": {
        "items": {
            "patternProperties": {
                ".*": {
                    "type": "string"
                }
            },
            "type": "object"
        },
        "type": "array"
    },
    "unixTime": {
        "type": "integer"
    },
    "p_log_type": {
        "type": "string"
    },
    "p_row_id": {
        "type": "string"
    },
    "p_event_time": {
        "$schema": "http://json-schema.org/draft-04/schema#",
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
