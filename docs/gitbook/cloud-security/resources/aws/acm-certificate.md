---
description: >-
  This page provides an overview of the basics of AWS Certificate Manager (ACM)
  Certificate.
---

# ACM Certificate

## Resource Type

`AWS.ACM.Certificate`

## Resource ID Format

For ACM Certificates, the resource ID is the ARN as shown here:

`arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111`

## Background

The [ACM Certificate](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html) resource represents public SSL/TLS certificates on your AWS based websites and applications.

## Fields

The following table describes the Fields you can use:

| Field                     | Type     | Description                                                                                                        |
| :------------------------ | :------- | :----------------------------------------------------------------------------------------------------------------- |
| `CertificateAuthorityArn` | `String` | The Amazon Resource Name to the [Private CA](https://docs.aws.amazon.com/acm-pca/latest/userguide/PcaWelcome.html) |
| `DomainValidationOptions` | `List`   | Validation information of each domain name that occurs as a result of the `RequestCertificate` request             |
| `FailureReason`           | `String` | The reason the certificate request failed                                                                          |
| `NotAfter`                | `String` | The time after which the certificate is not valid                                                                  |
| `NotBefore`               | `String` | The time before which the certificate is not valid                                                                 |
| `Status`                  | `String` | `PENDING_VALIDATION | ISSUED | INACTIVE EXPIRED | VALIDATION_TIMED_OUT | REVOKED FAILED`                           |

## Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:acm:us-west-2:123456789012:certificate/aaaa-1111",
    "CertificateAuthorityArn": null,
    "DomainName": "staging.runpanther.xyz",
    "DomainValidationOptions": [
        {
            "DomainName": "example.com",
            "ResourceRecord": {
                "Name": "example.com.",
                "Type": "CNAME",
                "Value": "111.acm-validations.aws."
            },
            "ValidationDomain": "example.com",
            "ValidationEmails": null,
            "ValidationMethod": "DNS",
            "ValidationStatus": "SUCCESS"
        },
        {
            "DomainName": "*.example.com",
            "ResourceRecord": {
                "Name": "111.example.com.",
                "Type": "CNAME",
                "Value": "111.acm-validations.aws."
            },
            "ValidationDomain": "*.example.com",
            "ValidationEmails": null,
            "ValidationMethod": "DNS",
            "ValidationStatus": "SUCCESS"
        }
    ],
    "ExtendedKeyUsages": [
        {
            "Name": "TLS_WEB_CLIENT_AUTHENTICATION",
            "OID": "1.1.1.1.1.1.1.1.1"
        },
        {
            "Name": "TLS_WEB_SERVER_AUTHENTICATION",
            "OID": "2.2.2.2.2.2.2.2.2"
        }
    ],
    "FailureReason": null,
    "InUseBy": [
        "arn:aws:cloudfront::123456789012:distribution/AAAA"
    ],
    "IssuedAt": "2019-01-01T00:00:00Z",
    "Issuer": "Amazon",
    "KeyAlgorithm": "RSA-2048",
    "KeyUsages": [
        {
            "Name": "KEY_ENCIPHERMENT"
        },
        {
            "Name": "DIGITAL_SIGNATURE"
        }
    ],
    "Name": "example.com",
    "NotAfter": "2020-01-01T00:00:00Z",
    "NotBefore": "2019-01-01T00:00:00Z",
    "Options": {
        "CertificateTransparencyLoggingPreference": "ENABLED"
    },
    "Region": "us-west-2",
    "RenewalEligibility": "ELIGIBLE",
    "RenewalSummary": null,
    "ResourceId": "arn:aws:acm:us-west-2:123456789012:certificate/aaaa-1111",
    "ResourceType": "AWS.ACM.Certificate",
    "RevocationReason": null,
    "RevokedAt": null,
    "Serial": "00:00:00:00:00:00:00:00:00:00:00:00:de:ad:be:ef",
    "SignatureAlgorithm": "SHA256WITHRSA",
    "Status": "ISSUED",
    "Subject": "CN=staging.runpanther.xyz",
    "SubjectAlternativeNames": [
        "example.com",
        "*.example.com"
    ],
    "Tags": null,
    "TimeCreated": null,
    "Type": "AMAZON_ISSUED"
}
```

## References

- [ACM Concepts](https://docs.aws.amazon.com/acm/latest/userguide/acm-concepts.html)
