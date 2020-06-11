# AWS Application Load Balancer Has Web ACL

| Risk     | Remediation Effort |
| :------- | :----------------- |
| **High** | **Medium**         |

This policy validates that each AWS Elastic Load Balancer is protected by the correct AWS WAF Web ACL. This can prevent many attacks before they reach your web servers, including XSS and SQL injection attacks.

This policy requires configuration before it can be enabled.

**Remediation**

To remediate this, assign a WAF Web ACL to the load balancer from the AWS [WAF panel](https://console.aws.amazon.com/wafv2/home?#/webacls/rules/).

<table>
  <thead>
    <tr>
      <th style="text-align:left">Using the AWS Console</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">1. Selecting the region that the WAF and load balancer exist in from the <code>Filter</code> dropdown</td>
    </tr>
    <tr>
      <td style="text-align:left">2. Selecting the Web ACL you would like to associate to the load balancer
        (one must be created if one does not already exist in the specified region)</td>
    </tr>
    <tr>
      <td style="text-align:left">3. Selecting the <code>Rules</code> tab</td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p></p>
        <p>4. Selecting the <code>Add association</code> button</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p></p>
        <p>5. Selecting the appropriate resource type in the <code>Resource type</code> dropdown</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p></p>
        <p>6. Selecting the desired load balancer from the <code>Resource</code> dropdown</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">
        <p></p>
        <p>7. Selecting the <code>Add</code> button</p>
      </td>
    </tr>
  </tbody>
</table>**References**

- AWS [WAF Web ACL](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-cloudfront-distribution.html) documentation
