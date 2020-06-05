---
description: Web Application Firewall (WAF) Web Access Control List (ACL)
---

# WAF Web ACL

#### Resource Types

`AWS.WAF.WebACL`, `AWS.WAF.Regional.WebACL`

#### Resource ID Format

For WAF Web ACLs, the resource ID is the ARN.

`arn:aws:waf::123456789012:webacl/1`

`arn:aws:waf-regional:us-west-2:123456789012:webacl/1`

#### Background

A web access control list \(web ACL\) gives you fine-grained control over the web requests that your Amazon API Gateway API, Amazon CloudFront distribution or Application Load Balancer responds to. Global Web ACLs apply to CloudFront and API Gateway. Regional Web ACLs apply to load balancers.

WAF Regional and Global ACLs are represented in the same fashion, the distinction is made to assist in writing rules for the correct scope.

#### Fields

[WebACL Reference](https://docs.aws.amazon.com/waf/latest/APIReference/API_WebACL.html)

| Field           | Type     | Description                                                                                                       |
| :-------------- | :------- | :---------------------------------------------------------------------------------------------------------------- |
| `Rules`         | `List`   | Lists each rule being applied by the WebACL, its priority \(ordering\), and the action taken, among other things. |
| `DefaultAction` | `Map`    | The default action for AWS WAF to allow web requests or to block web requests.                                    |
| `MetricName`    | `String` | A friendly name or description for the metrics for this WebACL.                                                   |

#### Example

```javascript
{
    "AccountId": "123456789012",
    "Arn": "arn:aws:waf-regional:us-west-2:123456789012:webacl/1",
    "DefaultAction": {
        "Type": "ALLOW"
    },
    "Id": "1",
    "MetricName": "metric-1",
    "Name": "example-web-acl",
    "Region": "us-west-2",
    "ResourceId": "arn:aws:waf-regional:us-west-2:123456789012:webacl/1",
    "ResourceType": "AWS.WAF.Regional.WebACL",
    "Rules": [
        {
            "Action": {
                "Type": "BLOCK"
            },
            "ExcludedRules": null,
            "MetricName": "metric-1",
            "Name": "rule-1",
            "OverrideAction": null,
            "Predicates": [
                {
                    "DataId": "1",
                    "Negated": false,
                    "Type": "XssMatch"
                }
            ],
            "Priority": 2,
            "RuleId": "1",
            "Type": "REGULAR"
        },
        {
            "Action": {
                "Type": "COUNT"
            },
            "ExcludedRules": null,
            "MetricName": "metric-2",
            "Name": "rule-2",
            "OverrideAction": null,
            "Predicates": [
                {
                    "DataId": "2",
                    "Negated": false,
                    "Type": "XssMatch"
                }
            ],
            "Priority": 1,
            "RuleId": "2",
            "Type": "REGULAR"
        }
    ],
    "Tags": null,
    "TimeCreated": null
}
```
