package parsers_test

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

// func BenchmarkReflectRepackJSON(b *testing.B) {

// 	log := `{"Records": [{"eventVersion":"1.05","userIdentity":{"type":"AWSService","invokedBy":"cloudtrail.amazonaws.com"},"eventTime":"2018-08-26T14:17:23Z","eventSource":"kms.amazonaws.com","eventName":"GenerateDataKey","awsRegion":"us-west-2","sourceIPAddress":"cloudtrail.amazonaws.com","userAgent":"cloudtrail.amazonaws.com","requestParameters":{"keySpec":"AES_256","encryptionContext":{"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail","aws:s3:arn":"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"},"keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"},"responseElements":null,"requestID":"3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086","eventID":"7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2","readOnly":true,"resources":[{"ARN":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0","accountId":"888888888888","type":"AWS::KMS::Key"}],"eventType":"AwsApiCall","recipientAccountId":"777777777777","sharedEventID":"238c190c-1a30-4756-8e08-19fc36ad1b9f"}]}`
// 	records := awslogs.CloudTrailRecords{}
// 	if err := jsoniter.UnmarshalFromString(log, &records); err != nil {
// 		b.Error(err)
// 	}
// 	event := records.Records[0]
// 	pEvent := event.PantherEvent()
// 	pantherLog := awslogs.PantherLogFactory(pEvent.LogType, pEvent.Timestamp, pEvent.Fields...)
// 	_, err := parsers.ComposeStruct(&event, pantherLog)
// 	if err != nil {
// 		b.Error(err)
// 	}
// 	for i := 0; i < b.N; i++ {
// 		tmp, err := parsers.ComposeStruct(event, pantherLog)
// 		if err != nil {
// 			b.Error(err)
// 		}
// 		data, err := jsoniter.Marshal(tmp.Interface())
// 		if err != nil {
// 			b.Error(err)
// 		}
// 		// Prevent optimizing data out
// 		_ = data
// 	}

// }
// func BenchmarkConcatRepackJSON(b *testing.B) {

// 	log := `{"Records": [{"eventVersion":"1.05","userIdentity":{"type":"AWSService","invokedBy":"cloudtrail.amazonaws.com"},"eventTime":"2018-08-26T14:17:23Z","eventSource":"kms.amazonaws.com","eventName":"GenerateDataKey","awsRegion":"us-west-2","sourceIPAddress":"cloudtrail.amazonaws.com","userAgent":"cloudtrail.amazonaws.com","requestParameters":{"keySpec":"AES_256","encryptionContext":{"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail","aws:s3:arn":"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"},"keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"},"responseElements":null,"requestID":"3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086","eventID":"7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2","readOnly":true,"resources":[{"ARN":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0","accountId":"888888888888","type":"AWS::KMS::Key"}],"eventType":"AwsApiCall","recipientAccountId":"777777777777","sharedEventID":"238c190c-1a30-4756-8e08-19fc36ad1b9f"}]}`
// 	records := awslogs.CloudTrailRecords{}
// 	if err := jsoniter.UnmarshalFromString(log, &records); err != nil {
// 		b.Error(err)
// 	}
// 	event := records.Records[0]
// 	pEvent := event.PantherEvent()
// 	p := awslogs.PantherLogFactory(pEvent.LogType, pEvent.Timestamp, pEvent.Fields...)
// 	for i := 0; i < b.N; i++ {
// 		objA, err := jsoniter.Marshal(event)
// 		if err != nil {
// 			b.Error(err)
// 		}

// 		objB, err := jsoniter.Marshal(p)
// 		if err != nil {
// 			b.Error(err)
// 		}
// 		data, err := jsontricks.ConcatObjects(objA, objB)
// 		if err != nil {
// 			b.Error(err)
// 		}
// 		// Prevent optimizing data out
// 		_ = data
// 	}

// }

// func BenchmarkEmbeddedRepackJSON(b *testing.B) {

// 	log := `{"Records": [{"eventVersion":"1.05","userIdentity":{"type":"AWSService","invokedBy":"cloudtrail.amazonaws.com"},"eventTime":"2018-08-26T14:17:23Z","eventSource":"kms.amazonaws.com","eventName":"GenerateDataKey","awsRegion":"us-west-2","sourceIPAddress":"cloudtrail.amazonaws.com","userAgent":"cloudtrail.amazonaws.com","requestParameters":{"keySpec":"AES_256","encryptionContext":{"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail","aws:s3:arn":"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"},"keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"},"responseElements":null,"requestID":"3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086","eventID":"7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2","readOnly":true,"resources":[{"ARN":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0","accountId":"888888888888","type":"AWS::KMS::Key"}],"eventType":"AwsApiCall","recipientAccountId":"777777777777","sharedEventID":"238c190c-1a30-4756-8e08-19fc36ad1b9f"}]}`
// 	records := awslogs.CloudTrailRecords{}
// 	if err := jsoniter.UnmarshalFromString(log, &records); err != nil {
// 		b.Error(err)
// 	}
// 	event := records.Records[0]
// 	type pantherLog struct {
// 		awslogs.CloudTrail
// 		pantherlog.Meta
// 	}
// 	pEvent := event.PantherEvent()
// 	p := struct {
// 		awslogs.CloudTrail
// 		awslogs.AWSPantherLog
// 	}{
// 		CloudTrail:    *event,
// 		AWSPantherLog: *awslogs.PantherLogFactory(pEvent.LogType, pEvent.Timestamp, pEvent.Fields...).(*awslogs.AWSPantherLog),
// 	}
// 	for i := 0; i < b.N; i++ {
// 		data, err := jsoniter.Marshal(&p)
// 		if err != nil {
// 			b.Error(err)
// 		}
// 		// Prevent optimizing data out
// 		_ = data
// 	}

// }
// func BenchmarkUnmarshalJSONIter(b *testing.B) {
// 	log := `{"Records": [{"eventVersion":"1.05","userIdentity":{"type":"AWSService","invokedBy":"cloudtrail.amazonaws.com"},"eventTime":"2018-08-26T14:17:23Z","eventSource":"kms.amazonaws.com","eventName":"GenerateDataKey","awsRegion":"us-west-2","sourceIPAddress":"cloudtrail.amazonaws.com","userAgent":"cloudtrail.amazonaws.com","requestParameters":{"keySpec":"AES_256","encryptionContext":{"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail","aws:s3:arn":"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"},"keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"},"responseElements":null,"requestID":"3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086","eventID":"7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2","readOnly":true,"resources":[{"ARN":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0","accountId":"888888888888","type":"AWS::KMS::Key"}],"eventType":"AwsApiCall","recipientAccountId":"777777777777","sharedEventID":"238c190c-1a30-4756-8e08-19fc36ad1b9f"}]}`
// 	records := awslogs.CloudTrailRecords{}
// 	for i := 0; i < b.N; i++ {
// 		err := jsoniter.UnmarshalFromString(log, &records)
// 		if err != nil {
// 			b.Error(err)
// 		}
// 	}
// }
// func BenchmarkUnmarshalGJSON(b *testing.B) {
// 	log := `{"Records": [{"eventVersion":"1.05","userIdentity":{"type":"AWSService","invokedBy":"cloudtrail.amazonaws.com"},"eventTime":"2018-08-26T14:17:23Z","eventSource":"kms.amazonaws.com","eventName":"GenerateDataKey","awsRegion":"us-west-2","sourceIPAddress":"cloudtrail.amazonaws.com","userAgent":"cloudtrail.amazonaws.com","requestParameters":{"keySpec":"AES_256","encryptionContext":{"aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail","aws:s3:arn":"arn:aws:s3:::panther-lab-cloudtrail/AWSLogs/888888888888/CloudTrail/us-west-2/2018/08/26/888888888888_CloudTrail_us-west-2_20180826T1410Z_inUwlhwpSGtlqmIN.json.gz"},"keyId":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0"},"responseElements":null,"requestID":"3cff2472-5a91-4bd9-b6d2-8a7a1aaa9086","eventID":"7a215e16-e0ad-4f6c-82b9-33ff6bbdedd2","readOnly":true,"resources":[{"ARN":"arn:aws:kms:us-west-2:888888888888:key/72c37aae-1000-4058-93d4-86374c0fe9a0","accountId":"888888888888","type":"AWS::KMS::Key"}],"eventType":"AwsApiCall","recipientAccountId":"777777777777","sharedEventID":"238c190c-1a30-4756-8e08-19fc36ad1b9f"}]}`
// 	for i := 0; i < b.N; i++ {
// 		result := gjson.Parse(log)
// 		if result.Type != gjson.JSON {
// 			b.Error("invalid JSON type")
// 		}
// 		v := result.Get("Records.0.userIdentity.type")
// 		if v.Str != "AWSService" {
// 			b.Error("invalid service" + v.Str)
// 		}
// 		{
// 			v := result.Get("Records.0.eventVersion")
// 			if v.Str != "1.05" {
// 				b.Error("invalid service" + v.Str)
// 			}

// 		}
// 	}
// }
