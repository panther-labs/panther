# Example queries

Please note that all queries should be qualified with partition columns (year, month, day, hour) for performance reasons.

## Did this IP address have any activity in my network (and in what logs)?

This is often one of the first questions asked in an investigation. Given there is some known bad indicator such as an IP address, then if there is related activity in your network/systems, a detailed investigation will be needed.

Panther makes asking such questions easy using the 'all_logs' Athena view which will search all data for the indicator of interest. Since most often the answers to these question are negative, making this a fast and efficient operation reduces investigation time.

In this example the Panther field `p_any_ip_addresses` is used. Panther extracts a number of common indicator fields over all data sources into standard fields (see [Panther Fields](../../log-analysis/panther-fields.md)).

```sql
SELECT
 p_log_type, count(1) AS row_count
FROM panther_views.all_logs
WHERE year=2020 AND month=1 AND day=31 AND contains(p_any_ip_addresses, '1.2.3.4')
GROUP BY p_log_type
```

## What are the top 10 IPs by row count over all logs?

Ranking activity (top or bottom) is a useful technique to gain visibility into a network. High ranking activity might
help locate IP addresses involved in a DDOS attack while low ranking (change ORDER BY to ASC) might highlight sneaky activity.

```sql
SELECT
  ip,
  count(1) as total_rows
FROM panther_views.all_logs
CROSS JOIN UNNEST(p_any_ip_addresses) AS t(ip)
WHERE year=2020 AND month=1 AND day=23
GROUP BY ip
ORDER BY  total_rows DESC
LIMIT 10
```

## What are the top 10 IPs by log type over all logs?

This is a variant of the above query where we are ranking the IPs by how many data sources they show activity. This shows
the degree of "reach" the IP address has over all your systems.

```sql
SELECT
  ip,
  count(distinct p_log_type) as datasets
FROM
(
SELECT
  p_log_type,
  ip
FROM panther_views.all_logs
CROSS JOIN UNNEST(p_any_ip_addresses) AS t(ip)
WHERE year=2020 AND month=1 AND day=23
GROUP BY ip, p_log_type
)
GROUP BY ip
ORDER BY  datasets DESC
LIMIT 10
```

## Show VPC Flowlog activity for SSH and RDP

Remote shells typically have a human at one end. During an investigation, isolating sessions from SSH and RDP is often
a standard procedure to identify specific actor activity.

```sql
SELECT
 *
FROM panther_logs.aws_vpcflow
WHERE
  year=2020 AND month=1 AND day=23
  AND
  srcport IN (22, 3389) or dstport IN (22, 3389)
ORDER BY p_event_time ASC
```

## Show VPC Flowlog activity for an IP address

During an investigation often particular IP addresses are identified as being of interest (e.g, a known command and control node).
Once the role of an IP address is identified, isolating and explaining that activity is of interest. This
can indicate which resources are likely to be compromised.

```sql
SELECT
 *
FROM panther_logs.aws_vpcflow
WHERE year=2020 AND month=1 AND day=31 AND contains(p_any_ip_addresses, '1.2.3.4')
ORDER BY p_event_time ASC
```

## Show VPC Flowlog activity related to CloudTrail sourceIPAddresses doing console signins

If there are concerns of a credential breach, then accounting for all AWS console activity
is of critical importance. This query will find all the CloudTrail sourceIPaddresses
involved in console signins and then return all the VPC Flow activity related. This will
show if there are common IP addresses. Of particular interest are IP addresses **outside of your organization**
communicating with the instances as well as logging into the console. This may indicate a compromise where
an unauthorized actor is accessing account resources.

```sql
WITH cloudTrailIPs as
(SELECT
  DISTINCT sourceIPAddress AS ip
 FROM panther_logs.aws_cloudtrail
 WHERE
    year=2020 AND month=2 AND day=1
    AND
    eventtype = 'AwsConsoleSignIn'
)
SELECT
 *
FROM  cloudTrailIPs ips JOIN panther_logs.aws_vpcflow flow ON (ips.ip = flow.srcaddr OR ips.ip = flow.dstaddr)
WHERE
  year=2020 AND month=2 AND day=1
ORDER BY p_event_time ASC
```

## Find all console "root" signins in CloudTrail

The root account should almost never sign into the AWS console; find all such signins.

```sql
SELECT
 *
FROM panther_logs.aws_cloudtrail
WHERE
  year=2020 AND month=1 AND day=23
  AND
  eventtype = 'AwsConsoleSignIn'
  AND
  useridentity.arn LIKE '%root%'
ORDER BY p_event_time ASC
```

## Find all of the sourceIPAddresses for console logins in CloudTrail and rank

This query is similar to the above query, with the IP addresses ranked for all console logins. This helps identify which
IP addresses are signing into the console while ranking the relative activity. This can often highlight
anomalous behaviors.

```sql
SELECT
 sourceipaddress,
 count(1) as total_rows
FROM panther_logs.aws_cloudtrail
WHERE
  year=2020 AND month=1 AND day=23
  AND
  eventtype = 'AwsConsoleSignIn'
GROUP BY sourceipaddress
ORDER BY total_rows DESC
```

## Show CloudTrail activity related to an AWS instance

During an investigation a particular instance may become the focus. For example, if it is compromised.
This query uses the the Panther field `p_any_aws_instance_ids` to easily search over all CloudTrail events for
any related activity.

```sql
SELECT
 *
FROM panther_logs.aws_cloudtrail
WHERE year=2020 AND month=1 AND contains(p_any_aws_instance_ids, 'i-0c4f541ef2f82481c')
ORDER BY p_event_time ASC
```

## Show CloudTrail activity related to an AWS role

Similar to the above query, the Panther field `p_any_aws_arns` can be used to quickly and easily find
all CloudTrail activity related to an ARN of interest (perhaps an ARN of role known to be compromised).

```sql
SELECT
 *
FROM panther_logs.aws_cloudtrail
WHERE year=2020 AND month=1 AND contains(p_any_aws_arns, 'arn:aws:iam::123456789012:role/SomeRole')
ORDER BY p_event_time ASC
```

## Show CloudTrail activity related to an AWS account id

This is another variation of using a Panther field to broadly query. In this case finding all CloudTrail
data related to an account of interest using `p_any_aws_account_ids` (perhaps the account is compromised and the concern is lateral movement).

```sql
SELECT
 *
FROM panther_logs.aws_cloudtrail
WHERE year=2020 AND month=1 AND contains(p_any_aws_account_ids, '123456789012')
ORDER BY p_event_time ASC
```

## Show all instance launches in CloudTrail

Often when credentials have been breached, there is concern about an actor creating or modifying infrastructure. The
below query finds all RunInstances commands. These should be reviewed for anomalous activity. For example, actors
have been known to spin-up large numbers of GPU instances for bitcoin mining in compromised accounts.

```sql
SELECT
 p_event_time,
 p_any_aws_instance_ids
FROM panther_logs.aws_cloudtrail
WHERE year=2020 AND month=1 AND eventname = 'RunInstances'
ORDER BY p_event_time ASC
```

## Rank all GuardDuty alerts by severity

GuardDuty is a valuable source of visibility into threats against your infrastructure. However, it can produce
a large number of findings. This query shows the distribution of findings which be used to assess the posture of
an account.

```sql
SELECT
 severity,
 count(1) AS total_rows
FROM panther_logs.aws_guardduty
WHERE year=2020 AND month=1
GROUP BY severity
ORDER BY total_rows DESC
```

## Rank all GuardDuty alerts by affected resources

Similar to the above example, but in this example the query characterizes the findings by ranking affected resources.

```sql
SELECT
 json_extract(resource, '$.resourcetype') AS resource_type,
 count(1) AS total_rows
FROM panther_logs.aws_guardduty
WHERE year=2020 AND month=1
GROUP BY json_extract(resource, '$.resourcetype')
ORDER BY total_rows DESC
```

## Find the DISTINCT IP addresses communicating with an S3 bucket and rank

The misconfiguration of S3 buckets is a major threat vector. If an open bucket is detected that was not intended to be
world readable, it is of critical importance to understand if there were any inappropriate accesses. This query
will collect and rank all IP addresses accessing the bucket of interest. These should be reviewed to determine if any are
outside your organization (**if so, you may have had a data leak**).

```sql
SELECT
 remoteip,
 count(1) AS total_rows
FROM panther_logs.aws_s3serveraccess
WHERE
  year=2020 AND month=1
  AND
  bucket='somebucket'
GROUP BY remoteip
ORDER BY total_rows DESC
```

## Rank UserAgent strings over all Nginx and ALB logs

This query will characterize activity by UserAgent over ALB and Nginx logs. This can be useful in an investigation,
if an actor has a known set of characteristic UserAgents.

```sql
SELECT
 useragent,
 sum(row_count) AS total_rows
FROM (

SELECT
 useragent,
 count(1) AS row_count
FROM panther_logs.aws_alb
WHERE year=2020 AND month=1 AND day=31
GROUP BY useragent

UNION ALL

SELECT
 httpuseragent AS useragent,
 count(1) AS row_count
FROM panther_logs.nginx_access
WHERE year=2020 AND month=1 AND day=31
GROUP BY httpuseragent
)
GROUP BY useragent
ORDER BY total_rows DESC
```
