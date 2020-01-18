package awslogs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestGuardDutyLogIAMUserLoggingConfigurationModified(t *testing.T) {
	//nolint
	log := `{"schemaVersion":"2.0","accountId":"123456789012","region":"eu-west-1","partition":"aws","id":"44b7c4e9781822beb75d3fbd518abf5b","arn":"arn:aws:guardduty:eu-west-1:123456789012:detector/b2b7c4e8df224d1b74bece34cc2cf1d5/finding/44b7c4e9781822beb75d3fbd518abf5b","type":"Stealth:IAMUser/LoggingConfigurationModified","resource":{"resourceType":"AccessKey","accessKeyDetails":{"accessKeyId":"GeneratedFindingAccessKeyId","principalId":"GeneratedFindingPrincipalId","userType":"IAMUser","userName":"GeneratedFindingUserName"}},"service":{"serviceName":"guardduty","detectorId":"b2b7c4e8df224d1b74bece34cc2cf1d5","action":{"actionType":"AWS_API_CALL","awsApiCallAction":{"api":"GeneratedFindingAPIName","serviceName":"GeneratedFindingAPIServiceName","callerType":"Remote IP","remoteIpDetails":{"ipAddressV4":"198.51.100.0","organization":{"asn":"-1","asnOrg":"GeneratedFindingASNOrg","isp":"GeneratedFindingISP","org":"GeneratedFindingORG"},"country":{"countryName":"GeneratedFindingCountryName"},"city":{"cityName":"GeneratedFindingCityName"},"geoLocation":{"lat":0,"lon":0}},"affectedResources":{}}},"resourceRole":"TARGET","additionalInfo":{"recentApiCalls":[{"count":2,"api":"GeneratedFindingAPIName1"},{"count":2,"api":"GeneratedFindingAPIName2"}],"sample":true},"eventFirstSeen":"2018-08-26T14:17:23.000Z","eventLastSeen":"2018-08-26T14:17:23.000Z","archived":false,"count":20},"severity":5,"createdAt":"2018-08-26T14:17:23.000Z","updatedAt":"2018-08-26T14:17:23.000Z","title":"Unusual changes to API activity logging by GeneratedFindingUserName.","description":"APIs commonly used to stop CloudTrail logging, delete existing logs and other such activity that erases any trace of activity in the account, was invoked by IAM principal GeneratedFindingUserName. Such activity is not typically seen from this principal."}`

	expectedDate := time.Unix(1535293043, 0).In(time.UTC)
	expectedEvent := &GuardDuty{
		SchemaVersion: aws.String("2.0"),
		AccountID:     aws.String("123456789012"),
		Region:        aws.String("eu-west-1"),
		Partition:     aws.String("aws"),
		ID:            aws.String("44b7c4e9781822beb75d3fbd518abf5b"),
		//nolint
		Arn:      aws.String("arn:aws:guardduty:eu-west-1:123456789012:detector/b2b7c4e8df224d1b74bece34cc2cf1d5/finding/44b7c4e9781822beb75d3fbd518abf5b"),
		Type:     aws.String("Stealth:IAMUser/LoggingConfigurationModified"),
		Severity: aws.Int(5),
		Title:    aws.String("Unusual changes to API activity logging by GeneratedFindingUserName."),
		//nolint
		Description: aws.String("APIs commonly used to stop CloudTrail logging, delete existing logs and other such activity that erases any trace of activity in the account, was invoked by IAM principal GeneratedFindingUserName. Such activity is not typically seen from this principal."),
		CreatedAt:   (*timestamp.RFC3339)(&expectedDate),
		UpdatedAt:   (*timestamp.RFC3339)(&expectedDate),
		Resource: map[string]interface{}{
			"resourceType": "AccessKey",
			"accessKeyDetails": map[string]interface{}{
				"accessKeyId": "GeneratedFindingAccessKeyId",
				"principalId": "GeneratedFindingPrincipalId",
				"userType":    "IAMUser",
				"userName":    "GeneratedFindingUserName",
			},
		},
		Service: &GuardDutyService{
			AdditionalInfo: map[string]interface{}{
				"recentApiCalls": []interface{}{
					map[string]interface{}{
						"api":   "GeneratedFindingAPIName1",
						"count": float64(2),
					},
					map[string]interface{}{
						"api":   "GeneratedFindingAPIName2",
						"count": float64(2),
					},
				},
				"sample": true,
			},
			Action: map[string]interface{}{
				"actionType": "AWS_API_CALL",
				"awsApiCallAction": map[string]interface{}{
					"api":               "GeneratedFindingAPIName",
					"affectedResources": map[string]interface{}{},
					"callerType":        "Remote IP",
					"serviceName":       "GeneratedFindingAPIServiceName",
					"remoteIpDetails": map[string]interface{}{
						"city": map[string]interface{}{
							"cityName": "GeneratedFindingCityName",
						},
						"country": map[string]interface{}{
							"countryName": "GeneratedFindingCountryName",
						},
						"geoLocation": map[string]interface{}{
							"lat": float64(0),
							"lon": float64(0),
						},
						"ipAddressV4": "198.51.100.0",
						"organization": map[string]interface{}{
							"asn":    "-1",
							"asnOrg": "GeneratedFindingASNOrg",
							"isp":    "GeneratedFindingISP",
							"org":    "GeneratedFindingORG",
						},
					},
				},
			},
			ServiceName:    aws.String("guardduty"),
			DetectorID:     aws.String("b2b7c4e8df224d1b74bece34cc2cf1d5"),
			ResourceRole:   aws.String("TARGET"),
			EventFirstSeen: (*timestamp.RFC3339)(&expectedDate),
			EventLastSeen:  (*timestamp.RFC3339)(&expectedDate),
			Archived:       aws.Bool(false),
			Count:          aws.Int(20),
		},
	}

	parser := &GuardDutyParser{}
	require.Equal(t, []interface{}{expectedEvent}, parser.Parse(log))
}

func TestGuardDutyLogEC2DGADomainRequest(t *testing.T) {
	//nolint
	log := `{"schemaVersion":"2.0","accountId":"123456789012","region":"eu-west-1","partition":"aws","id":"96b7c4e9781a57ad76e82080578d7d56","arn":"arn:aws:guardduty:eu-west-1:123456789012:detector/b2b7c4e8df224d1b74bece34cc2cf1d5/finding/96b7c4e9781a57ad76e82080578d7d56","type":"Trojan:EC2/DGADomainRequest.B","resource":{"resourceType":"Instance","instanceDetails":{"instanceId":"i-99999999","instanceType":"m3.xlarge","launchTime":"2018-08-26T14:17:23Z","instanceState":"running","availabilityZone":"GeneratedFindingInstaceAvailabilityZone","imageId":"ami-99999999","imageDescription":"GeneratedFindingInstaceImageDescription"}},"service":{"serviceName":"guardduty","detectorId":"b2b7c4e8df224d1b74bece34cc2cf1d5","action":{"actionType":"DNS_REQUEST","dnsRequestAction":{"domain":"GeneratedFindingDomainName","protocol":"0","blocked":true}},"resourceRole":"ACTOR","additionalInfo":{"domain":"GeneratedFindingAdditionalDomainName","sample":true},"eventFirstSeen":"2018-08-26T14:17:23.000Z","eventLastSeen":"2018-08-26T14:17:23.000Z","archived":false,"count":18},"severity":8,"createdAt":"2018-08-26T14:17:23.000Z","updatedAt":"2018-08-26T14:17:23.000Z","title":"DGA domain name queried by EC2 instance i-99999999.","description":"EC2 instance i-99999999 is querying algorithmically generated domains. Such domains are commonly used by malware and could be an indication of a compromised EC2 instance."}`

	expectedDate := time.Unix(1535293043, 0).In(time.UTC)
	expectedEvent := &GuardDuty{
		SchemaVersion: aws.String("2.0"),
		AccountID:     aws.String("123456789012"),
		Region:        aws.String("eu-west-1"),
		Partition:     aws.String("aws"),
		ID:            aws.String("96b7c4e9781a57ad76e82080578d7d56"),
		//nolint
		Arn:      aws.String("arn:aws:guardduty:eu-west-1:123456789012:detector/b2b7c4e8df224d1b74bece34cc2cf1d5/finding/96b7c4e9781a57ad76e82080578d7d56"),
		Type:     aws.String("Trojan:EC2/DGADomainRequest.B"),
		Severity: aws.Int(8),
		Title:    aws.String("DGA domain name queried by EC2 instance i-99999999."),
		//nolint
		Description: aws.String("EC2 instance i-99999999 is querying algorithmically generated domains. Such domains are commonly used by malware and could be an indication of a compromised EC2 instance."),
		CreatedAt:   (*timestamp.RFC3339)(&expectedDate),
		UpdatedAt:   (*timestamp.RFC3339)(&expectedDate),
		Resource: map[string]interface{}{
			"resourceType": "Instance",
			"instanceDetails": map[string]interface{}{
				"instanceId":       "i-99999999",
				"instanceType":     "m3.xlarge",
				"launchTime":       "2018-08-26T14:17:23Z",
				"instanceState":    "running",
				"availabilityZone": "GeneratedFindingInstaceAvailabilityZone",
				"imageId":          "ami-99999999",
				"imageDescription": "GeneratedFindingInstaceImageDescription",
			},
		},
		Service: &GuardDutyService{
			AdditionalInfo: map[string]interface{}{
				"domain": "GeneratedFindingAdditionalDomainName",
				"sample": true,
			},
			Action: map[string]interface{}{
				"actionType": "DNS_REQUEST",
				"dnsRequestAction": map[string]interface{}{
					"domain":   "GeneratedFindingDomainName",
					"protocol": "0",
					"blocked":  true,
				},
			},
			ServiceName:    aws.String("guardduty"),
			DetectorID:     aws.String("b2b7c4e8df224d1b74bece34cc2cf1d5"),
			ResourceRole:   aws.String("ACTOR"),
			EventFirstSeen: (*timestamp.RFC3339)(&expectedDate),
			EventLastSeen:  (*timestamp.RFC3339)(&expectedDate),
			Archived:       aws.Bool(false),
			Count:          aws.Int(18),
		},
	}

	parser := &GuardDutyParser{}
	require.Equal(t, []interface{}{expectedEvent}, parser.Parse(log))
}

func TestGuardDutyLogMissingRequiredField(t *testing.T) {
	log := `{"schemaVersion":"2.0","region":"eu-west-1","partition":"aws"}`
	parser := &GuardDutyParser{}
	require.Nil(t, parser.Parse(log))
}

func TestGuardDutyLogType(t *testing.T) {
	parser := &GuardDutyParser{}
	require.Equal(t, "AWS.GuardDuty", parser.LogType())
}
