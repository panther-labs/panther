package awslogs

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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
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
		Severity: aws.Float32(5),
		Title:    aws.String("Unusual changes to API activity logging by GeneratedFindingUserName."),
		//nolint
		Description: aws.String("APIs commonly used to stop CloudTrail logging, delete existing logs and other such activity that erases any trace of activity in the account, was invoked by IAM principal GeneratedFindingUserName. Such activity is not typically seen from this principal."),
		CreatedAt:   (*timestamp.RFC3339)(&expectedDate),
		UpdatedAt:   (*timestamp.RFC3339)(&expectedDate),
		Resource:    newRawMessage(`{"resourceType":"AccessKey","accessKeyDetails":{"accessKeyId":"GeneratedFindingAccessKeyId","principalId":"GeneratedFindingPrincipalId","userType":"IAMUser","userName":"GeneratedFindingUserName"}}`), // nolint(lll)
		Service: &GuardDutyService{
			AdditionalInfo: newRawMessage(`{"recentApiCalls":[{"count":2,"api":"GeneratedFindingAPIName1"},{"count":2,"api":"GeneratedFindingAPIName2"}],"sample":true}`),                                                                                                                                                                                                                                                                                                                                                                    // nolint(lll)
			Action:         newRawMessage(`{"actionType":"AWS_API_CALL","awsApiCallAction":{"api":"GeneratedFindingAPIName","serviceName":"GeneratedFindingAPIServiceName","callerType":"Remote IP","remoteIpDetails":{"ipAddressV4":"198.51.100.0","organization":{"asn":"-1","asnOrg":"GeneratedFindingASNOrg","isp":"GeneratedFindingISP","org":"GeneratedFindingORG"},"country":{"countryName":"GeneratedFindingCountryName"},"city":{"cityName":"GeneratedFindingCityName"},"geoLocation":{"lat":0,"lon":0}},"affectedResources":{}}}`), // nolint(lll)
			ServiceName:    aws.String("guardduty"),
			DetectorID:     aws.String("b2b7c4e8df224d1b74bece34cc2cf1d5"),
			ResourceRole:   aws.String("TARGET"),
			EventFirstSeen: (*timestamp.RFC3339)(&expectedDate),
			EventLastSeen:  (*timestamp.RFC3339)(&expectedDate),
			Archived:       aws.Bool(false),
			Count:          aws.Int(20),
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.GuardDuty")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDate)
	expectedEvent.AppendAnyIPAddress("198.51.100.0")
	expectedEvent.AppendAnyAWSAccountIds("123456789012")
	// nolint(lll)
	expectedEvent.AppendAnyAWSARNs("arn:aws:guardduty:eu-west-1:123456789012:detector/b2b7c4e8df224d1b74bece34cc2cf1d5/finding/44b7c4e9781822beb75d3fbd518abf5b")

	checkGuardDutyLog(t, log, expectedEvent)
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
		Arn:      aws.String("arn:aws:guardduty:eu-west-1:123456789012:detector/b2b7c4e8df224d1b74bece34cc2cf1d5/finding/96b7c4e9781a57ad76e82080578d7d56"), // nolint(lll)
		Type:     aws.String("Trojan:EC2/DGADomainRequest.B"),
		Severity: aws.Float32(8),
		Title:    aws.String("DGA domain name queried by EC2 instance i-99999999."),
		//nolint
		Description: aws.String("EC2 instance i-99999999 is querying algorithmically generated domains. Such domains are commonly used by malware and could be an indication of a compromised EC2 instance."), // nolint(lll)
		CreatedAt:   (*timestamp.RFC3339)(&expectedDate),
		UpdatedAt:   (*timestamp.RFC3339)(&expectedDate),
		Resource:    newRawMessage(`{"resourceType":"Instance","instanceDetails":{"instanceId":"i-99999999","instanceType":"m3.xlarge","launchTime":"2018-08-26T14:17:23Z","instanceState":"running","availabilityZone":"GeneratedFindingInstaceAvailabilityZone","imageId":"ami-99999999","imageDescription":"GeneratedFindingInstaceImageDescription"}}`), // nolint(lll)
		Service: &GuardDutyService{
			AdditionalInfo: newRawMessage(`{"domain":"GeneratedFindingAdditionalDomainName","sample":true}`),
			Action:         newRawMessage(`{"actionType":"DNS_REQUEST","dnsRequestAction":{"domain":"GeneratedFindingDomainName","protocol":"0","blocked":true}}`), // nolint(lll)
			ServiceName:    aws.String("guardduty"),
			DetectorID:     aws.String("b2b7c4e8df224d1b74bece34cc2cf1d5"),
			ResourceRole:   aws.String("ACTOR"),
			EventFirstSeen: (*timestamp.RFC3339)(&expectedDate),
			EventLastSeen:  (*timestamp.RFC3339)(&expectedDate),
			Archived:       aws.Bool(false),
			Count:          aws.Int(18),
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.GuardDuty")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDate)
	expectedEvent.AppendAnyAWSInstanceIds("i-99999999")
	expectedEvent.AppendAnyAWSAccountIds("123456789012")
	expectedEvent.AppendAnyDomainNames("GeneratedFindingDomainName", "GeneratedFindingAdditionalDomainName")
	// nolint(lll)
	expectedEvent.AppendAnyAWSARNs("arn:aws:guardduty:eu-west-1:123456789012:detector/b2b7c4e8df224d1b74bece34cc2cf1d5/finding/96b7c4e9781a57ad76e82080578d7d56") // nolint(lll)

	checkGuardDutyLog(t, log, expectedEvent)
}

func TestGuardDutyLogSSHBruteForce(t *testing.T) {
	// nolint
	log := `{"schemaVersion":"2.0","accountId":"123456789012","region":"us-east-1","partition":"aws","id":"70b7e42a3241b4c73d8d8cf7b1781f7e","arn":"arn:aws:guardduty:us-east-1:123456789012:detector/6eb7d75a6563c71411485bf5e38adb2f/finding/70b7e42a3241b4c73d8d8cf7b1781f7e","type":"UnauthorizedAccess:EC2/SSHBruteForce","resource":{"resourceType":"Instance","instanceDetails":{"platform":null,"tags":[{"key":"tag1","value":"val1"}],"availabilityZone":"us-east-1b","imageDescription":"Amazon Linux 2 AMI 2.0.20191217.0 x86_64 HVM gp2","instanceId":"i-081de1d7604b11e4a","instanceType":"t2.micro","launchTime":"2020-01-13T20:22:32Z","productCodes":[],"iamInstanceProfile":{"id":"AIPAQXSBWDWTIWB5KZKXA","arn":"arn:aws:iam::123456789012:instance-profile/EC2Dev"},"networkInterfaces":[{"subnetId":"subnet-48998e66","privateDnsName":"ip-172-31-81-237.ec2.internal","publicIp":"54.152.215.140","networkInterfaceId":"eni-0fd8e8a70bb7804e3","vpcId":"vpc-4a486c30","securityGroups":[{"groupName":"launch-wizard-31","groupId":"sg-0225c1ef2723cd87d"}],"ipv6Addresses":["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],"publicDnsName":"ec2-54-152-215-140.compute-1.amazonaws.com","privateIpAddress":"172.31.81.237","privateIpAddresses":[{"privateDnsName":"ip-172-31-81-237.ec2.internal","privateIpAddress":"172.31.81.237"}]}],"instanceState":"running","imageId":"ami-062f7200baf2fa504"}},"severity":2,"createdAt":"2018-08-26T14:17:23.000Z","updatedAt":"2018-08-26T14:17:23.000Z","title":"151.80.19.228 is performing SSH brute force attacks against i-081de1d7604b11e4a. ","description":"151.80.19.228 is performing SSH brute force attacks against i-081de1d7604b11e4a. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password.","service":{"additionalInfo":{},"action":{"actionType":"NETWORK_CONNECTION","networkConnectionAction":{"localPortDetails":{"portName":"SSH","port":22},"protocol":"TCP","blocked":false,"connectionDirection":"INBOUND","remoteIpDetails":{"ipAddressV4":"151.80.19.228","organization":{"asn":"16276","asnOrg":"OVH SAS","isp":"OVH SAS","org":"OVH SAS"},"country":{"countryName":"France"},"city":{"cityName":"Roubaix"},"geoLocation":{"lon":3.178,"lat":50.6974}},"remotePortDetails":{"port":32938,"portName":"Unknown"}}},"serviceName":"guardduty","detectorId":"6eb7d75a6563c71411485bf5e38adb2f","resourceRole":"TARGET","eventFirstSeen":"2018-08-26T14:17:23.000Z","eventLastSeen":"2018-08-26T14:17:23.000Z","archived":false,"count":3}}`

	expectedDate := time.Unix(1535293043, 0).In(time.UTC)
	expectedEvent := &GuardDuty{
		SchemaVersion: aws.String("2.0"),
		AccountID:     aws.String("123456789012"),
		Region:        aws.String("us-east-1"),
		Partition:     aws.String("aws"),
		ID:            aws.String("70b7e42a3241b4c73d8d8cf7b1781f7e"),
		//nolint
		Arn:      aws.String("arn:aws:guardduty:us-east-1:123456789012:detector/6eb7d75a6563c71411485bf5e38adb2f/finding/70b7e42a3241b4c73d8d8cf7b1781f7e"), // nolint(lll)
		Type:     aws.String("UnauthorizedAccess:EC2/SSHBruteForce"),
		Severity: aws.Float32(2),
		Title:    aws.String("151.80.19.228 is performing SSH brute force attacks against i-081de1d7604b11e4a. "),
		//nolint
		Description: aws.String("151.80.19.228 is performing SSH brute force attacks against i-081de1d7604b11e4a. Brute force attacks are used to gain unauthorized access to your instance by guessing the SSH password."), // nolint(lll)
		CreatedAt:   (*timestamp.RFC3339)(&expectedDate),
		UpdatedAt:   (*timestamp.RFC3339)(&expectedDate),
		Resource:    newRawMessage(`{"resourceType":"Instance","instanceDetails":{"platform":null,"tags":[{"key":"tag1","value":"val1"}],"availabilityZone":"us-east-1b","imageDescription":"Amazon Linux 2 AMI 2.0.20191217.0 x86_64 HVM gp2","instanceId":"i-081de1d7604b11e4a","instanceType":"t2.micro","launchTime":"2020-01-13T20:22:32Z","productCodes":[],"iamInstanceProfile":{"id":"AIPAQXSBWDWTIWB5KZKXA","arn":"arn:aws:iam::123456789012:instance-profile/EC2Dev"},"networkInterfaces":[{"subnetId":"subnet-48998e66","privateDnsName":"ip-172-31-81-237.ec2.internal","publicIp":"54.152.215.140","networkInterfaceId":"eni-0fd8e8a70bb7804e3","vpcId":"vpc-4a486c30","securityGroups":[{"groupName":"launch-wizard-31","groupId":"sg-0225c1ef2723cd87d"}],"ipv6Addresses":["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],"publicDnsName":"ec2-54-152-215-140.compute-1.amazonaws.com","privateIpAddress":"172.31.81.237","privateIpAddresses":[{"privateDnsName":"ip-172-31-81-237.ec2.internal","privateIpAddress":"172.31.81.237"}]}],"instanceState":"running","imageId":"ami-062f7200baf2fa504"}}`), // nolint(lll)
		Service: &GuardDutyService{
			AdditionalInfo: newRawMessage(`{}`),
			Action:         newRawMessage(`{"actionType":"NETWORK_CONNECTION","networkConnectionAction":{"localPortDetails":{"portName":"SSH","port":22},"protocol":"TCP","blocked":false,"connectionDirection":"INBOUND","remoteIpDetails":{"ipAddressV4":"151.80.19.228","organization":{"asn":"16276","asnOrg":"OVH SAS","isp":"OVH SAS","org":"OVH SAS"},"country":{"countryName":"France"},"city":{"cityName":"Roubaix"},"geoLocation":{"lon":3.178,"lat":50.6974}},"remotePortDetails":{"port":32938,"portName":"Unknown"}}}`), // nolint(lll)
			ServiceName:    aws.String("guardduty"),
			DetectorID:     aws.String("6eb7d75a6563c71411485bf5e38adb2f"),
			ResourceRole:   aws.String("TARGET"),
			EventFirstSeen: (*timestamp.RFC3339)(&expectedDate),
			EventLastSeen:  (*timestamp.RFC3339)(&expectedDate),
			Archived:       aws.Bool(false),
			Count:          aws.Int(3),
		},
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.GuardDuty")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedDate)
	expectedEvent.AppendAnyAWSInstanceIds("i-081de1d7604b11e4a")
	expectedEvent.AppendAnyAWSAccountIds("123456789012")
	expectedEvent.AppendAnyIPAddress("54.152.215.140")
	expectedEvent.AppendAnyIPAddress("151.80.19.228")
	expectedEvent.AppendAnyIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	expectedEvent.AppendAnyIPAddress("172.31.81.237")
	expectedEvent.AppendAnyAWSTags("tag1:val1")
	expectedEvent.AppendAnyDomainNames("ec2-54-152-215-140.compute-1.amazonaws.com", "ip-172-31-81-237.ec2.internal")
	expectedEvent.AppendAnyAWSARNs("arn:aws:iam::123456789012:instance-profile/EC2Dev",
		"arn:aws:guardduty:us-east-1:123456789012:detector/6eb7d75a6563c71411485bf5e38adb2f/finding/70b7e42a3241b4c73d8d8cf7b1781f7e")

	checkGuardDutyLog(t, log, expectedEvent)
}

func TestGuardDutyLogMissingRequiredField(t *testing.T) {
	log := `{"schemaVersion":"2.0","region":"eu-west-1","partition":"aws"}`
	parser := &GuardDutyParser{}
	events, err := parser.Parse(log)
	require.Error(t, err)
	require.Nil(t, events)
}

func TestGuardDutyLogType(t *testing.T) {
	parser := &GuardDutyParser{}
	require.Equal(t, "AWS.GuardDuty", parser.LogType())
}

func checkGuardDutyLog(t *testing.T, log string, expectedEvent *GuardDuty) {
	expectedEvent.SetEvent(expectedEvent)
	parser := &GuardDutyParser{}
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}
