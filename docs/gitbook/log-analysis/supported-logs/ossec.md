# OSSEC Logs

[OSSEC](https://www.ossec.net/) is a widely used open source host intrusion detection system. Panther supports the JSON `alerts.json` log file format for OSSEC EventInfo alerts.

| Log Type          | Reference                                           |
| ----------------- | --------------------------------------------------- |
| `OSSEC.EventInfo` | https://www.ossec.net/docs/docs/formats/alerts.html |

## OSSEC.EventInfo

```json
{
    "id": {
        "type": "string"
    },
    "rule": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/Rule"
    },
    "TimeStamp": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/UnixMillisecond"
    },
    "location": {
        "type": "string"
    },
    "hostname": {
        "type": "string"
    },
    "full_log": {
        "type": "string"
    },
    "action": {
        "type": "string"
    },
    "agentip": {
        "type": "string"
    },
    "agent_name": {
        "type": "string"
    },
    "command": {
        "type": "string"
    },
    "data": {
        "type": "string"
    },
    "decoder": {
        "type": "string"
    },
    "decoder_desc": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/Decoder"
    },
    "decoder_parent": {
        "type": "string"
    },
    "dstgeoip": {
        "type": "string"
    },
    "dstip": {
        "type": "string"
    },
    "dstport": {
        "type": "string"
    },
    "dstuser": {
        "type": "string"
    },
    "logfile": {
        "type": "string"
    },
    "previous_output": {
        "type": "string"
    },
    "program_name": {
        "type": "string"
    },
    "protocol": {
        "type": "string"
    },
    "srcgeoip": {
        "type": "string"
    },
    "srcip": {
        "type": "string"
    },
    "srcport": {
        "type": "string"
    },
    "srcuser": {
        "type": "string"
    },
    "status": {
        "type": "string"
    },
    "SyscheckFile": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/FileDiff"
    },
    "systemname": {
        "type": "string"
    },
    "url": {
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

### Decoder

```json
{
    "accumulate": {
        "type": "integer"
    },
    "fts": {
        "type": "integer"
    },
    "ftscomment": {
        "type": "string"
    },
    "name": {
        "type": "string"
    },
    "parent": {
        "type": "string"
    }
}
```

### FileDiff

```json
{
    "gowner_after": {
        "type": "string"
    },
    "gowner_before": {
        "type": "string"
    },
    "md5_after": {
        "type": "string"
    },
    "md5_before": {
        "type": "string"
    },
    "owner_after": {
        "type": "string"
    },
    "owner_before": {
        "type": "string"
    },
    "path": {
        "type": "string"
    },
    "perm_after": {
        "type": "integer"
    },
    "perm_before": {
        "type": "integer"
    },
    "sha1_after": {
        "type": "string"
    },
    "sha1_before": {
        "type": "string"
    }
}
```

### Rule

```json
{
    "comment": {
        "type": "string"
    },
    "group": {
        "type": "string"
    },
    "level": {
        "type": "integer"
    },
    "sidid": {
        "type": "integer"
    },
    "CIS": {
        "items": {
            "type": "string"
        },
        "type": "array"
    },
    "cve": {
        "type": "string"
    },
    "firedtimes": {
        "type": "integer"
    },
    "frequency": {
        "type": "integer"
    },
    "groups": {
        "items": {
            "type": "string"
        },
        "type": "array"
    },
    "info": {
        "type": "string"
    },
    "PCI_DSS": {
        "items": {
            "type": "string"
        },
        "type": "array"
    }
}
```
