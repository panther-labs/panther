---
description: Key Management Service (KMS) Key
---

# KMS Key

#### Resource Type

`AWS.KMS.Key`

#### Resource ID Format

For KMS Keys, the resource ID is the ARN.

`arn:aws:kms:us-west-2:123456789012:key/1`

#### Background

KMS is a service to create and manage encryption keys for across a wide range of AWS services and within your applications.

#### Fields

| Field                | Type     | Description                                                   |
| :------------------- | :------- | :------------------------------------------------------------ |
| `KeyRotationEnabled` | `Bool`   | If key rotation is enabled for this KMS key                   |
| `Policy`             | `String` | A JSON policy document indicating what has access to this key |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:kms:us-west-2:123456789012:key/1",
    "CloudHsmClusterId": null,
    "CustomKeyStoreId": null,
    "DeletionDate": null,
    "Description": "Default master key that protects my ACM private keys when no other key is defined",
    "Enabled": true,
    "ExpirationModel": null,
    "Id": "1",
    "KeyManager": "AWS",
    "KeyRotationEnabled": null,
    "KeyState": "Enabled",
    "KeyUsage": "ENCRYPT_DECRYPT",
    "Origin": "AWS_KMS",
    "Policy": "{\n  \"Version\" : \"2012-10-17\",\n  \"Id\" : \"auto-acm-3\",\n  \"Statement\" : [ {\n    \"Sid\" : \"Allow creation of decryption grants\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : {\n      \"AWS\" : \"*\"\n    },\n    \"Action\" : \"kms:CreateGrant\",\n    \"Resource\" : \"*\",\n    \"Condition\" : {\n      \"StringEquals\" : {\n        \"kms:CallerAccount\" : \"123456789012\",\n        \"kms:ViaService\" : \"acm.us-east-1.amazonaws.com\"\n      },\n      \"ForAllValues:StringEquals\" : {\n        \"kms:GrantOperations\" : \"Decrypt\"\n      },\n      \"Bool\" : {\n        \"kms:GrantIsForAWSResource\" : \"true\"\n      }\n    }\n  }, {\n    \"Sid\" : \"Allow creation of encryption grant\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : {\n      \"AWS\" : \"*\"\n    },\n    \"Action\" : \"kms:CreateGrant\",\n    \"Resource\" : \"*\",\n    \"Condition\" : {\n      \"StringEquals\" : {\n        \"kms:CallerAccount\" : \"123456789012\",\n        \"kms:ViaService\" : \"acm.us-east-1.amazonaws.com\"\n      },\n      \"ForAllValues:StringEquals\" : {\n        \"kms:GrantOperations\" : [ \"Encrypt\", \"ReEncryptFrom\", \"ReEncryptTo\" ]\n      },\n      \"Bool\" : {\n        \"kms:GrantIsForAWSResource\" : \"true\"\n      }\n    }\n  }, {\n    \"Sid\" : \"Allowed operations for the key owner\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : {\n      \"AWS\" : \"*\"\n    },\n    \"Action\" : [ \"kms:DescribeKey\", \"kms:ListGrants\", \"kms:RevokeGrant\", \"kms:GetKeyPolicy\" ],\n    \"Resource\" : \"*\",\n    \"Condition\" : {\n      \"StringEquals\" : {\n        \"kms:CallerAccount\" : \"123456789012\"\n      }\n    }\n  }, {\n    \"Sid\" : \"Deny re-encryption to any other key\",\n    \"Effect\" : \"Deny\",\n    \"Principal\" : {\n      \"AWS\" : \"*\"\n    },\n    \"Action\" : \"kms:ReEncrypt*\",\n    \"Resource\" : \"*\",\n    \"Condition\" : {\n      \"Bool\" : {\n        \"kms:ReEncryptOnSameKey\" : \"false\"\n      }\n    }\n  } ]\n}",
    "Region": "us-west-2",
    "ResourceId": "arn:aws:kms:us-west-2:123456789012:key/1",
    "ResourceType": "AWS.KMS.Key",
    "Tags": null,
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "ValidTo": null
}
```
