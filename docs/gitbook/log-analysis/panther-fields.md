# Panther's Standard Fields

Panther's log analysis applies normalization fields (IPs, domains, etc) to all log records. These fields provide standard names for attributes across all data sources enabling fast and easy data correlation.

For example, each data source has a time that an event occurred, but each data source will likely not name the attribute the same, nor is it guaranteed that the associated time has a timezone consistent with other data sources.

The Panther attribute `p_event_time` is mapped to each data source's corresponding event time and normalized to UTC. This way you can query over multiple data sources joining and ordering by `p_event_time` to properly align and correlate the data despite the disparate schemas of each data source.

{% hint style="info" %}
All appended standard fields begin with `p_`
{% endhint %}

## Required Fields

The fields below are appended to all log records:

| Field Name        | Type        | Description                                                                      |
| ----------------- | ----------- | -------------------------------------------------------------------------------- |
| `p_log_type`      | `string`    | The type of log.                                                                 |
| `p_row_id`        | `string`    | Unique id (UUID) for the row.                                                    |
| `p_event_time`    | `timestamp` | The associated event time for the log type is copied here and normalized to UTC. |
| `p_parse_time`    | `timestamp` | The current time when the event was parsed normalized to UTC.                    |
| `p_source_id`     | `string`    | The id of the source that the log was read from.                                 |
| `p_source_label`  | `string`    | The label of the source that the log was read from.                              |

{% hint style="info" %}
If an event does not have a timestamp, then `p_event_time` will be set to `p_parse_time`, which is the time the event was parsed.
{% endhint %}

## The "any" Fields

A common security question is often of the form of: “was some-indicator ever observed in our logs?”

Notice that the relationship of the indicator is not a concern initially, simply the presence or absence of activity is of interest.

To allow this question to be answered over all data sources the "any" fields below are appended to rows of data as appropriate.

The `all_logs` view is provided over all data sources to make queries easy for users to find activity for an indicator in a single query.

| Field Name               | Type             | Description                                                    |
| ------------------------ | ---------------- | -------------------------------------------------------------- |
| `p_alert_id`             | `string`         | Id of alert related to row.                                    |
| `p_alert_creation_time`  | `timestamp`      | Time of alert creation related to row.                         |
| `p_alert_update_time`    | `timestamp`      | Time of last alert update related to row.                      |
| `p_any_aws_account_ids`  | `array[string]`  | List of aws account ids related to row.                        |
| `p_any_aws_arns`         | `array[string]`  | List of aws arns related to row.                               |
| `p_any_aws_instance_ids` | `array[string]`  | List of aws instance ids related to row.                       |
| `p_any_aws_tags`         | `array[string]`  | List of aws tags related to row as "key:value" pairs.          |
| `p_any_domain_names`     | `array[string]`  | List of domain names related to row.                           |
| `p_any_ip_addresses`     | `array[string]`  | List of ip addresses (v4 or v6 in string form) related to row. |
| `p_any_md5_hashes`       | `array[string]`  | List of MD5 hashes related to row.                             |
| `p_any_sha1_hashes`      | `array[string]`  | List of SHA1 hashes related to row.                            |
| `p_any_sha256_hashes`    | `array[string]`  | List of SHA256 hashes related to row.                          |
| `p_rule_reports`         | `map[string]array[string]` | List of user defined rule reporting tags related to row.  |
| `p_rule_tags`            | `array[string]`  | List of user defined rule tags related to row.                 |


## The "all_logs" View

Panther manages a view over all data sources with standard fields.

This allows you to ask questions such as "was there _any_ activity from some-bad-ip and if so where?".

The query below will show how many records (by log type) are associated with IP address `95.123.145.92`:

```sql
SELECT
 p_log_type, count(1) AS row_count
FROM panther_views.all_logs
WHERE year=2020 AND month=1 AND day=31 AND contains(p_any_ip_addresses, '95.123.145.92')
GROUP BY p_log_type
```

From these results, you can pivot to the specific logs where activity is indicated.

## Standard Fields in Rules

The Panther standard fields can be used in rules. For example, this rule triggers when any
GuardDuty alert is on a resource tagged as 'critical':

![Example Panther Rule](../.gitbook/assets/log-analysis/panther-fields.png)
