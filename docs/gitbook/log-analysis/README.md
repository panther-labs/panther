# Log Analysis

Panther's Log Analysis is used to parse, normalize, and analyze high volumes of log data in real-time. In order to onboard into this pipeline, data must send to  an S3 bucket. Data can also be organized using S3 folders or multiple buckets.

![](../.gitbook/assets/panther_graphic_flow.jpg)

Common events analyzed with log analysis include:
* Authorization or authentication
* API calls
* Network traffic
* Running processes
* Alerts from IDS

## How It Works

1. Logs are written into an S3 bucket
2. The bucket sends an event notification to Panther's SNS Topic
3. Panther receives the event notification, assumes an IAM Role, and downloads the log data
4. The parsed log data is forwarded for analysis
