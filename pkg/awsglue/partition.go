package awsglue

/**
 * Copyright 2020 Panther Labs Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Meta data about GlueTableMetadata table over parser data written to S3
// NOTE: this struct has all accessor behind functions to allow a lazy evaluation
//       so the cost of creating the schema is only when actually needing this information.

type GluePartition struct {
	tableMetadata  *GlueTableMetadata
	s3ObjectKey string
	dataFormat string // Can currently be only "json"
	compression *string // an only be "gzip" or empty
	partitions map[string]string
}

func PartitionFromS3Key(s3ObjectKey string) *GluePartition {

}


