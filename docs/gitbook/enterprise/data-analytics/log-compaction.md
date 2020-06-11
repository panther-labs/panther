# Automatic Log Compaction

Searching in Panther Enterprise is 10 times faster and uses 60% less storage. This means you get more done for less money.

The community edition of Panther stores all log data as gzipped compressed JSON files in S3. While JSON is a flexible
file format, it requires complex parsing (slow to search) and takes up considerable space relative to binary file formats (expensive to store).

Panther Enterprise automatically:
* Coalesces log files to the optimal number per hourly partition
   * Fewer files means faster searching
* Compresses JSON data into  [Parquet](https://en.wikipedia.org/wiki/Apache_Parquet), a columnar file format
   * Files are typically 60% smaller than gzipped JSON files, you pay less for storage.
   * The columnar format means that when you search, the query only reads the columns you specify. Less data means faster queries and lower cost.

Panther's compacted data is compatible with most `data lake` tools like Athena, Spark, EMR and SageMaker.

There is nothing to tune or configure. Simply upgrade to Panther Enterprise. Your Athena queries will fly while your data costs go down.
