# Built-in Packs

By default, rules and policies are pre-installed from Panther's [open source packs](https://github.com/panther-labs/panther-analysis) to help teams establish baseline detections.

The packs are grouped into:
- AWS CIS
- AWS Best Practices
- AWS Services (VPC, S3, CloudTrail, and more)
- Osquery

{% hint style="success" %}
For Enterprise customers, additional packs are provided for MITRE ATT&CK, Cisco Umbrella, GCP Audit, and more.
{% endhint %}

## Severities

There are many standards on what different severity levels should mean.

At Panther we base our severities on this table:

| Severity   | Exploitability | Description                        | Examples                                                                                                                           |
| :--------- | :------------- | :--------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------- |
| `Info`     | `None`         | No risk, simply informational      | Name formatting, missing tags. General best practices for ops.                                                                     |
| `Low`      | `Difficult`    | Little to no risk if exploited     | Non sensitive information leaking such as system time and OS versions.                                                             |
| `Medium`   | `Difficult`    | Moderate risk if exploited         | Expired credentials, missing protection against accidental data loss, encryption settings, best practice settings for audit tools. |
| `High`     | `Moderate`     | Very damaging if exploited         | Large gaps in visibility, directly vulnerable infrastructure, misconfigurations directly related to data exposure.                 |
| `Critical` | `Easy`         | Causes extreme damage if exploited | Public data or systems, leaked access keys.                                                                                        |

Feel free to use this as a reference point, or create your own standards.
