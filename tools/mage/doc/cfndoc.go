package doc

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/panther-labs/panther/tools/mage/util"
)

/*
This looks for tagged comments in CloudFormation resources and extracts them for documentation.

The tags <cfndoc> (to open) and </cfndoc> (to close) are used. The resource immediately above the
tags is extracted as the label. The rest of the text is used as documentation. Lines leading with '#' have the '#' skipped.

Example:
Resources:
  # SQS Queue, DLQ and Lambda
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: panther-input-data-notifications
      # <cfndoc>
      # This sqs queue receives S3 notifications
      # of log files to be processed.
      # </cfndoc>

      KmsMasterKeyId: !Ref SQSKeyId
      # Reference on KeyReuse: https://amzn.to/2ngIsFB
      KmsDataKeyReusePeriodSeconds: 3600 # 1 hour
      VisibilityTimeout: 180 # Should match lambda
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt DeadLetterQueue.Arn
        maxReceiveCount: 10
*/

// TODO - Parse CfnDoc as yaml field instead of comment, then group by resource type
const (
	StartTag = `<cfndoc>`
	EndTag   = `</cfndoc>`
)

var (
	commentMarkers      = regexp.MustCompile(`\n\s*[#]`)
	extractResourceDocs = regexp.MustCompile(`(?s)([[:alpha:]]+):[ \t]*(\S+)[\s\#]*` + StartTag + `(.+?)` + EndTag)
)

type ResourceDoc struct {
	FieldName     string // "QueueName", "FunctionName", etc
	Resource      string // referenced label
	Documentation string
}

func ReadCfn(paths ...string) (docs []*ResourceDoc, err error) {
	for _, path := range paths {
		fileDocs := Parse(string(util.MustReadFile(path)))
		docs = append(docs, fileDocs...)
	}
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Resource == docs[j].Resource {
			// Same resource name: break ties by resource "type" based on field name
			return docs[i].FieldName < docs[j].FieldName
		}

		return docs[i].Resource < docs[j].Resource
	})

	return docs, nil
}

func Parse(cfn string) (docs []*ResourceDoc) {
	for _, match := range extractResourceDocs.FindAllStringSubmatch(cfn, -1) {
		if len(match) != 4 {
			panic(fmt.Sprintf("bad match, likely regexp is wrong: %#v", match))
		}
		docs = append(docs, &ResourceDoc{
			FieldName:     match[1],
			Resource:      match[2],
			Documentation: clean(match[3]),
		})
	}
	return docs
}

func clean(s string) string {
	// we want to allow # so markdown can work but remove the leading # comment markers
	return strings.TrimSpace(commentMarkers.ReplaceAllString(s, "\n"))
}
