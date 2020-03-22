# AWS Logs

AWS contains a variety of critical data sources used to audit API usage, database calls, network traffic, and more.

| Log Type               | Reference                                                                                          |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| `AWS.ALB`              | https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html |
| `AWS.AuroraMySQLAudit` | https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html             |
| `AWS.CloudTrail`       | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html         |
| `AWS.GuardDuty`        | https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html                      |
| `AWS.S3ServerAccess`   | https://docs.aws.amazon.com/AmazonS3/latest/dev/LogFormat.html                                     |
| `AWS.VPCFlow`          | https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html                   |

## AWS.ALB

The schema below represents AWS Application Load Balancer (ALB) logs:

```json
{
  "type": {
    "type": "string"
  },
  "timestamp": {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "$ref": "#/definitions/RFC3339"
  },
  "elb": {
    "type": "string"
  },
  "clientIp": {
    "type": "string"
  },
  "clientPort": {
    "type": "integer"
  },
  "targetIp": {
    "type": "string"
  },
  "targetPort": {
    "type": "integer"
  },
  "requestProcessingTime": {
    "type": "number"
  },
  "targetProcessingTime": {
    "type": "number"
  },
  "responseProcessingTime": {
    "type": "number"
  },
  "elbStatusCode": {
    "type": "integer"
  },
  "targetStatusCode": {
    "type": "integer"
  },
  "receivedBytes": {
    "type": "integer"
  },
  "sentBytes": {
    "type": "integer"
  },
  "requestHttpMethod": {
    "type": "string"
  },
  "requestUrl": {
    "type": "string"
  },
  "requestHttpVersion": {
    "type": "string"
  },
  "userAgent": {
    "type": "string"
  },
  "sslCipher": {
    "type": "string"
  },
  "sslProtocol": {
    "type": "string"
  },
  "targetGroupArn": {
    "type": "string"
  },
  "traceId": {
    "type": "string"
  },
  "domainName": {
    "type": "string"
  },
  "chosenCertArn": {
    "type": "string"
  },
  "matchedRulePriority": {
    "type": "integer"
  },
  "requestCreationTime": {
    "$ref": "#/definitions/RFC3339"
  },
  "actionsExecuted": {
    "items": {
      "type": "string"
    },
    "type": "array"
  },
  "redirectUrl": {
    "type": "string"
  },
  "errorReason": {
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
  },
  "p_any_aws_account_ids": {
    "$ref": "#/definitions/PantherAnyString"
  },
  "p_any_aws_instance_ids": {
    "$ref": "#/definitions/PantherAnyString"
  },
  "p_any_aws_arns": {
    "$ref": "#/definitions/PantherAnyString"
  },
  "p_any_aws_tags": {
    "$ref": "#/definitions/PantherAnyString"
  }
}
```

## AWS.CloudTrail

```json
{
    "additionalEventData": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    },
    "apiVersion": {
        "type": "string"
    },
    "awsRegion": {
        "type": "string"
    },
    "errorCode": {
        "type": "string"
    },
    "errorMessage": {
        "type": "string"
    },
    "eventId": {
        "type": "string"
    },
    "eventName": {
        "type": "string"
    },
    "eventSource": {
        "type": "string"
    },
    "eventTime": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "eventType": {
        "type": "string"
    },
    "eventVersion": {
        "type": "string"
    },
    "managementEvent": {
        "type": "boolean"
    },
    "readOnly": {
        "type": "boolean"
    },
    "recipientAccountId": {
        "type": "string"
    },
    "requestId": {
        "type": "string"
    },
    "requestParameters": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    },
    "resources": {
        "items": {
            "$schema": "http://json-schema.org/draft-04/schema#",
            "$ref": "#/definitions/CloudTrailResources"
        },
        "type": "array"
    },
    "responseElements": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    },
    "serviceEventDetails": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    },
    "sharedEventId": {
        "type": "string"
    },
    "sourceIpAddress": {
        "type": "string"
    },
    "userAgent": {
        "type": "string"
    },
    "userIdentity": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/CloudTrailUserIdentity"
    },
    "vpcEndpointId": {
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
    },
    "p_any_aws_account_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_instance_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_arns": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_tags": {
        "$ref": "#/definitions/PantherAnyString"
    }
}
```

### CloudTrailSessionContextAttributes

```json
{
    "mfaAuthenticated": {
        "type": "string"
    },
    "creationDate": {
        "type": "string"
    }
}
```

### CloudTrailUserIdentity

```json
{
    "type": {
        "type": "string"
    },
    "principalId": {
        "type": "string"
    },
    "arn": {
        "type": "string"
    },
    "accountId": {
        "type": "string"
    },
    "accessKeyId": {
        "type": "string"
    },
    "userName": {
        "type": "string"
    },
    "sessionContext": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/CloudTrailSessionContext"
    },
    "invokedBy": {
        "type": "string"
    },
    "identityProvider": {
        "type": "string"
    }
}
```

### CloudTrailSessionContext

```json
{
    "attributes": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/CloudTrailSessionContextAttributes"
    },
    "sessionIssuer": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/CloudTrailSessionContextSessionIssuer"
    },
    "webIdFederationData": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/CloudTrailSessionContextWebIDFederationData"
    }
}
```

### CloudTrailSessionContextSessionIssuer

```json
{
    "type": {
        "type": "string"
    },
    "principalId": {
        "type": "string"
    },
    "arn": {
        "type": "string"
    },
    "accountId": {
        "type": "string"
    },
    "userName": {
        "type": "string"
    }
}
```

### CloudTrailSessionContextWebIDFederationData

```json
{
    "federatedProvider": {
        "type": "string"
    },
    "attributes": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    }
}
```

### CloudTrailResources
```json
{
    "arn": {
        "type": "string"
    },
    "accountId": {
        "type": "string"
    },
    "type": {
        "type": "string"
    }
}
```

## AWS.S3ServerAccess

```json
{
    "bucketowner": {
        "type": "string"
    },
    "bucket": {
        "type": "string"
    },
    "time": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "remoteip": {
        "type": "string"
    },
    "requester": {
        "type": "string"
    },
    "requestid": {
        "type": "string"
    },
    "operation": {
        "type": "string"
    },
    "key": {
        "type": "string"
    },
    "requesturi": {
        "type": "string"
    },
    "httpstatus": {
        "type": "integer"
    },
    "errorcode": {
        "type": "string"
    },
    "bytessent": {
        "type": "integer"
    },
    "objectsize": {
        "type": "integer"
    },
    "totaltime": {
        "type": "integer"
    },
    "turnaroundtime": {
        "type": "integer"
    },
    "referrer": {
        "type": "string"
    },
    "useragent": {
        "type": "string"
    },
    "versionid": {
        "type": "string"
    },
    "hostid": {
        "type": "string"
    },
    "signatureversion": {
        "type": "string"
    },
    "ciphersuite": {
        "type": "string"
    },
    "authenticationtype": {
        "type": "string"
    },
    "hostheader": {
        "type": "string"
    },
    "tlsVersion": {
        "type": "string"
    },
    "additionalFields": {
        "items": {
            "type": "string"
        },
        "type": "array"
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
    },
    "p_any_aws_account_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_instance_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_arns": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_tags": {
        "$ref": "#/definitions/PantherAnyString"
    }
}
```

## AWS.VPCFlow

```json
{
    "version": {
        "type": "integer"
    },
    "account": {
        "type": "string"
    },
    "interfaceId": {
        "type": "string"
    },
    "srcAddr": {
        "type": "string"
    },
    "dstAddr": {
        "type": "string"
    },
    "srcPort": {
        "type": "integer"
    },
    "dstPort": {
        "type": "integer"
    },
    "protocol": {
        "type": "integer"
    },
    "packets": {
        "type": "integer"
    },
    "bytes": {
        "type": "integer"
    },
    "start": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "end": {
        "$ref": "#/definitions/RFC3339"
    },
    "action": {
        "type": "string"
    },
    "status": {
        "type": "string"
    },
    "vpcId": {
        "type": "string"
    },
    "subNetId": {
        "type": "string"
    },
    "instanceId": {
        "type": "string"
    },
    "tcpFlags": {
        "type": "integer"
    },
    "trafficType": {
        "type": "string"
    },
    "pktSrcAddr": {
        "type": "string"
    },
    "pktDstAddr": {
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
    },
    "p_any_aws_account_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_instance_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_arns": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_tags": {
        "$ref": "#/definitions/PantherAnyString"
    }
}
```

## AWS.AuroraMySQLAudit

```json
{
    "timestamp": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "serverHost": {
        "type": "string"
    },
    "username": {
        "type": "string"
    },
    "host": {
        "type": "string"
    },
    "connectionId": {
        "type": "integer"
    },
    "queryId": {
        "type": "integer"
    },
    "operation": {
        "type": "string"
    },
    "database": {
        "type": "string"
    },
    "object": {
        "type": "string"
    },
    "retCode": {
        "type": "integer"
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
    },
    "p_any_aws_account_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_instance_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_arns": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_tags": {
        "$ref": "#/definitions/PantherAnyString"
    }
}
```

## AWS.GuardDuty

```json
{
    "schemaVersion": {
        "type": "string"
    },
    "accountId": {
        "type": "string"
    },
    "region": {
        "type": "string"
    },
    "partition": {
        "type": "string"
    },
    "id": {
        "type": "string"
    },
    "arn": {
        "type": "string"
    },
    "type": {
        "type": "string"
    },
    "resource": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    },
    "severity": {
        "type": "number"
    },
    "createdAt": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/RFC3339"
    },
    "updatedAt": {
        "$ref": "#/definitions/RFC3339"
    },
    "title": {
        "type": "string"
    },
    "description": {
        "type": "string"
    },
    "service": {
        "$schema": "http://json-schema.org/draft-04/schema#",
        "$ref": "#/definitions/GuardDutyService"
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
    },
    "p_any_aws_account_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_instance_ids": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_arns": {
        "$ref": "#/definitions/PantherAnyString"
    },
    "p_any_aws_tags": {
        "$ref": "#/definitions/PantherAnyString"
    }
}
```

### GuardDutyService

```json
{
    "additionalInfo": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    },
    "action": {
        "items": {
            "type": "integer"
        },
        "type": "array"
    },
    "serviceName": {
        "type": "string"
    },
    "detectorId": {
        "type": "string"
    },
    "resourceRole": {
        "type": "string"
    },
    "eventFirstSeen": {
        "$ref": "#/definitions/RFC3339"
    },
    "eventLastSeen": {
        "$ref": "#/definitions/RFC3339"
    },
    "archived": {
        "type": "boolean"
    },
    "count": {
        "type": "integer"
    }
}
```
