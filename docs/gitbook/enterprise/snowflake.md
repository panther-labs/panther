# [Snowflake](https://www.snowflake.com) Database Integration
Panther can be configured to write processed log data to one or more
AWS-based Snowflake database clusters. This allows you to join Panther processed data
with your other data sources in Snowflake. 

Integrating Panther with Snowflake enables Panther data to be used in your Business Intelligence
tools to make dashboards tailored to you operations.  In addition you can join Panther data (e.g., Panther alerts)
to your business data, enabling assessment of your security posture with respect to your organization.
For example, you can tally alerts by organizational division (e.g., Human Resources) or by 
infrastructure (e.g., Development, Test, Production).

Panther uses [Snowpipe](https://docs.snowflake.com/en/user-guide/data-load-snowpipe-intro.html) to copy the data into your Snowflake cluster.

## Configuration

In order to configure Panther, you need to get the `SNOWFLAKE_IAM_USER` from Snowflake. In a 
Snowflake SQL shell execute the below sql, replacing `myaccountid` with your AWS account id
and `myaccountregion` with the account's region:
```sql
select system$get_aws_sns_iam_policy('arn:aws:sns:myaccountregion:myaccountid:panther-processed-data-notifications');
```
You should see a response like:
```json
{ 
 "Version":"2012-10-17",
 "Statement":[
  {
    "Sid":"1",
    "Effect":"Allow",
    "Principal":{
       "AWS":"arn:aws:iam::34318291XXXX:user/k7m2-s-v2st0722"
    },
    "Action":["sns:Subscribe"],
    "Resource":["arn:aws:sns:myaccountregion:myaccoundid:panther-processed-data-notifications"]
  }
 ] 
}
```
In the above example the `SNOWFLAKE_IAM_USER` is the `AWS` attribute `arn:aws:iam::34318291XXXX:user/k7m2-s-v2st0722`.

Edit `deployments/panther_config.yml` to add  `arn:aws:iam::34318291XXXX:user/k7m2-s-v2st0722` the  to Snowflake configuration:
```yaml
 # Snowflake (https://www.snowflake.com/) Integration
  Snowflake:
    # List of Snowflake cluster IAM ARNs which will ingest the output of Panther log processing.
    # If this list is non-empty, a file will be produced by `mage deploy`
    # called './out/snowflake/showpipe.sql' that should be run in your snowflake cluster
    # to configure Snowpipe and declare the Panther tables.
    # For example:
    # DestinationClusterARNs:
    #  - arn:aws:iam::34318291XXXX:user/k8m1-s-v2st0721 # test snowflake cluster
    #  - arn:aws:iam::34318291XXXX:user/h1h4-s-a2st0111 # production snowflake cluster
    DestinationClusterARNs:
      - arn:aws:iam::34318291XXXX:user/k7m2-s-v2st0722
```

Next run `mage deploy`.

When the deployment is done there should be a `snowpipe.sql` file created in:
```
./out/snowflake/snowpipe.sql
```

In the Snowflake SQL shell use the `Load Script` option to load `snowpipe.sql`. 
![Load](../.gitbook/assets/snowflake-upload.png)

Select the `All Queries` checkbox, then click on `Run`. 
![Run](../.gitbook/assets/snowflake-run.png)

## Validation
Once `snowpipe.sql` has been successfully executed, you should have three databases:
* panther_logs
* panther_rule_matches
* panther_views

These are the same database names used in AWS Athena and queries should behave similarly.

Assuming you have data being regularly being processed, there should be data in the tables
in a few minutes. 

You can quickly test if the data ingestion is working by running simple queries, for example:
```sql
select count(1) as c from panther_logs.public.aws_cloudtrail ;
```




