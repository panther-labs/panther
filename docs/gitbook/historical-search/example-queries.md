# Example queries

Please note that all queries should be qualified with partition columns (year, month, day, hour) for performance reasons.

## Did this IP address have any activity in my network (and in what logs)?

```sql
SELECT
 p_log_type, count(1) AS row_count
FROM panther_views.all_logs
WHERE year=2020 AND month=1 AND day=31 AND contains(p_any_ip_addresses, '1.2.3.4')
GROUP BY p_log_type
```

## What are the top 10 IPs by row count over all logs?

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

```sql
SELECT
 *
FROM panther_tables.aws_vpcflow
WHERE
  year=2020 AND month=1 AND day=23
  AND
  srcport IN (22, 3389) or dstport IN (22, 3389)
ORDER BY p_event_time ASC
```

## Find all console "root" logins in CloudTrail

```sql
SELECT
 *
FROM panther_tables.aws_cloudtrail
WHERE
  year=2020 AND month=1 AND day=23
  AND
  eventtype = 'AwsConsoleSignIn'
  AND
  useridentity.arn LIKE '%root%'
ORDER BY p_event_time ASC
```

## Show CloudTrail activity related to an AWS instance

```sql
SELECT
 *
FROM panther_tables.aws_cloudtrail
WHERE year=2020 AND month=1 AND contains(p_any_aws_instance_ids, 'i-0c4f541ef2f82481c')
ORDER BY p_event_time ASC
```

## Show CloudTrail activity related to an AWS role

```sql
SELECT
 *
FROM panther_tables.aws_cloudtrail
WHERE year=2020 AND month=1 AND contains(p_any_aws_arns, 'arn:aws:iam::123456789012:role/SomeRole')
ORDER BY p_event_time ASC

```

## Show CloudTrail activity related to an AWS account id

```sql
SELECT
 *
FROM panther_tables.aws_cloudtrail
WHERE year=2020 AND month=1 AND contains(p_any_aws_account_ids, '123456789012')
ORDER BY p_event_time ASC
```

## Show all instance launches in CloudTrail

```sql
SELECT
 *
FROM panther_tables.aws_cloudtrail
WHERE year=2020 AND month=1 AND eventname = 'RunInstances'
ORDER BY p_event_time ASC
```

## Rank all GuardDuty alerts by severity

```sql
SELECT
 severity,
 count(1) AS total_rows
FROM panther_tables.aws_guardduty
WHERE year=2020 AND month=1
GROUP BY severity
ORDER BY total_rows DESC
```

## Rank all GuardDuty alerts by affected resources

```sql
SELECT
 json_extract(resource, '$.resourcetype') AS resource_type,
 count(1) AS total_rows
FROM panther_tables.aws_guardduty
WHERE year=2020 AND month=1
GROUP BY json_extract(resource, '$.resourcetype')
ORDER BY total_rows DESC
```

## Find the DISTINCT IP addresses communicating with an S3 bucket and rank

```sql
SELECT
 remoteip,
 count(1) AS total_rows
FROM panther_tables.aws_s3serveraccess
WHERE
  year=2020 AND month=1
  AND
  bucket='somebucket'
GROUP BY remoteip
ORDER BY total_rows DESC
```

## Rank UserAgent strings over all Nginx and ALB logs

```sql
SELECT
 useragent,
 sum(row_count) AS total_rows
FROM (

SELECT
 useragent,
 count(1) AS row_count
FROM panther_tables.aws_alb
WHERE year=2020 AND month=1 AND day=31
GROUP BY useragent

UNION ALL

SELECT
 httpuseragent AS useragent,
 count(1) AS row_count
FROM panther_tables.nginx_access
WHERE year=2020 AND month=1 AND day=31
GROUP BY httpuseragent
)
GROUP BY useragent
ORDER BY total_rows DESC
```
