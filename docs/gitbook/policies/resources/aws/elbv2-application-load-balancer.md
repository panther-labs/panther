---
description: Elastic Load Balancer Version 2 (ELBV2) Application Load Balancer
---

# ELBV2 Application Load Balancer

#### Resource Type

`AWS.ELBV2.ApplicationLoadBalancer`

#### Resource ID Format

For ELBV2 Load Balancers, the resource ID is the ARN.

`arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/example-lb/1`

#### Background

This resource represents a snapshot of an AWS ELBv2 Application Load Balancer

| Field         | Type     | Description                                                                                                                                                                                                              |
| :------------ | :------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WebAcl`      | `String` | The associated AWS WAF Web ACL ID                                                                                                                                                                                        |
| `Listeners`   | `List`   | A list of maps, each of which corresponds to a listener on a certain port and it's associated actions                                                                                                                    |
| `SSLPolicies` | `Map`    | A description of the SSL ciphers and protocols supported by the load balancer. For each entry in `Listeners` that contains an `SSLPolicy`, there will be a corresponding entry here with the details of that `SSLPolicy` |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/example-lb/1",
    "AvailabilityZones": [
        {
            "LoadBalancerAddresses": null,
            "SubnetId": "subnet-1",
            "ZoneName": "us-west-2d"
        },
        {
            "LoadBalancerAddresses": null,
            "SubnetId": "subnet-1",
            "ZoneName": "us-west-2a"
        }
    ],
    "CanonicalHostedZonedId": "AAAA",
    "DNSName": "internal-example-lb-1111.us-west-2.elb.amazonaws.com",
    "IpAddressType": "ipv4",
    "Listeners": [
        {
            "Certificates": [
                {
                    "CertificateArn": "arn:aws:acm:us-west-2:123456789012:certificate/example-cert",
                    "IsDefault": null
                }
            ],
            "DefaultActions": [
                {
                    "AuthenticateCognitoConfig": null,
                    "AuthenticateOidcConfig": null,
                    "FixedResponseConfig": null,
                    "Order": null,
                    "RedirectConfig": null,
                    "TargetGroupArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:targetgroup/test-lb-target-group/1",
                    "Type": "forward"
                }
            ],
            "ListenerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:listener/app/example-lb/1/1",
            "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/example-lb/1",
            "Port": 443,
            "Protocol": "HTTPS",
            "SslPolicy": "ELBSecurityPolicy-2016-08"
        }
    ],
    "Name": "example-lb",
    "Region": "us-west-2",
    "ResourceId": "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/example-lb/1",
    "ResourceType": "AWS.ELBV2.ApplicationLoadBalancer",
    "SSLPolicies": {
        "ELBSecurityPolicy-2016-08": {
            "Ciphers": [
                {
                    "Name": "ECDHE-ECDSA-AES128-GCM-SHA256",
                    "Priority": 1
                },
                {
                    "Name": "ECDHE-RSA-AES128-GCM-SHA256",
                    "Priority": 2
                },
                {
                    "Name": "AES256-SHA",
                    "Priority": 3
                }
            ],
            "Name": "ELBSecurityPolicy-2016-08",
            "SslProtocols": [
                "TLSv1",
                "TLSv1.1",
                "TLSv1.2"
            ]
        }
    },
    "Scheme": "internal",
    "SecurityGroups": [
        "sg-1"
    ],
    "State": {
        "Code": "active",
        "Reason": null
    },
    "Tags": {
        "Key1": "Value1"
    },
    "TimeCreated": "2019-01-01T00:00:00.000Z",
    "Type": "application",
    "VpcId": "vpc-1",
    "WebAcl": "1111-2222-3333"
}
```
