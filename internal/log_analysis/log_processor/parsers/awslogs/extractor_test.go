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
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/pantherlog"
	"testing"

	jsoniter "github.com/json-iterator/go"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/extract"
)

const awsJSON = `
{

"accountId": "123456789012",

"encryptionContext": {
  "aws:cloudtrail:arn":"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail"
},

"instanceDetails":{
 "platform":null,
 "tags":[{"key":"tag1","value":"val1"}],
 "availabilityZone":"us-east-1b",
 "imageDescription":"Amazon Linux 2 AMI 2.0.20191217.0 x86_64 HVM gp2",
 "instanceId":"i-081de1d7604b11e4a","instanceType":"t2.micro",
 "launchTime":"2020-01-13T20:22:32Z",
  "productCodes":[],
  "iamInstanceProfile":{
    "id":"AIPAQXSBWDWTIWB5KZKXA",
    "arn":"arn:aws:iam::123456789012:instance-profile/EC2Dev"
   },
  "networkInterfaces":[
    {
      "subnetId":"subnet-48998e66",
      "privateDnsName":"ip-172-31-81-237.ec2.internal",
      "publicIp":"54.152.215.140",
      "networkInterfaceId":"eni-0fd8e8a70bb7804e3",
      "vpcId":"vpc-4a486c30","securityGroups":[
         {
           "groupName":"launch-wizard-31",
           "groupId":"sg-0225c1ef2723cd87d"
         }
      ],
      "ipv6Addresses":["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
      "publicDnsName":"ec2-54-152-215-140.compute-1.amazonaws.com",
      "privateIpAddress":"172.31.81.237",
      "privateIpAddresses":[
        {
          "privateDnsName":"ip-172-31-81-237.ec2.internal",
          "privateIpAddress":"172.31.81.237"
        }
      ]
    }
   ],
   "instanceState":"running",
   "imageId":"ami-062f7200baf2fa504"
},

"instanceArnExample": "arn:aws:ec2:region:111122223333:instance/i-0072230f74b3a798e",
"malformedArnExample": "arn:BUT-I-AM-NOT-REALLY-AN-ARN",
"malformedInstanceArnExample": "arn:aws:ec2:region:111122223333:instance/",

"DNSAction":{
  "actionType":"DNS_REQUEST",
  "dnsRequestAction":{
    "domain":"GeneratedFindingDomainName",
    "protocol":"0",
    "blocked":true
   }
},

"SSHAction":{
  "actionType":"NETWORK_CONNECTION",
  "networkConnectionAction":{
    "localPortDetails":{
       "portName":"SSH",
       "port":22
    },
    "protocol":"TCP",
    "blocked":false,
    "connectionDirection":"INBOUND",
    "remoteIpDetails":{ 
      "ipAddressV4":"151.80.19.228",
      "organization":{
        "asn":"16276",
        "asnOrg":"OVH SAS",
        "isp":"OVH SAS",
        "org":"OVH SAS"
      },
      "country":{
        "countryName":"France"
      },
      "city":{
        "cityName":"Roubaix"
      },
      "geoLocation":{"lon":3.178,"lat":50.6974}
     },
     "remotePortDetails":{"port":32938,"portName":"Unknown"}
  }
}

}
`

func TestAWSExtractor(t *testing.T) {
	event := AWSPantherLog{}
	// add interesting fragments as new extractions are implemented
	json := jsoniter.RawMessage(awsJSON)

	expectedEvent := AWSPantherLog{}
	expectedEvent.AppendAnyAWSARNs("arn:aws:iam::123456789012:instance-profile/EC2Dev",
		"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail",
		"arn:aws:ec2:region:111122223333:instance/i-0072230f74b3a798e",
		"arn:aws:ec2:region:111122223333:instance/")
	expectedEvent.AppendAnyAWSInstanceIds("i-081de1d7604b11e4a", "i-0072230f74b3a798e" /* from ARN */)
	expectedEvent.AppendAnyAWSAccountIds("123456789012", "888888888888" /* from ARN */, "111122223333" /* from ARN */)
	expectedEvent.AppendAnyIPAddress("54.152.215.140")
	expectedEvent.AppendAnyIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	expectedEvent.AppendAnyIPAddress("172.31.81.237")
	expectedEvent.AppendAnyIPAddress("151.80.19.228")
	expectedEvent.AppendAnyAWSTags("tag1:val1")
	expectedEvent.AppendAnyDomainNames("ec2-54-152-215-140.compute-1.amazonaws.com", "GeneratedFindingDomainName",
		"ip-172-31-81-237.ec2.internal")

	extract.Extract(&json, NewAWSExtractor(&event))

	require.Equal(t, expectedEvent, event)
}

func TestJSONScanner(t *testing.T) {
	scanner := JSONScanner()
	event := pantherlog.Event{}
	err := event.Scan(awsJSON, scanner)
	require.NoError(t, err)
	values := event.AppendValuesTo(nil)
	values = pantherlog.ValueSlice(values).Normalized()
	require.Equal(t, []pantherlog.Value{
		{
			Kind: pantherlog.KindIPAddress,
			Data: "151.80.19.228",
		},
		{
			Kind: pantherlog.KindIPAddress,
			Data: "172.31.81.237",
		},
		{
			Kind: pantherlog.KindIPAddress,
			Data: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		},
		{
			Kind: pantherlog.KindIPAddress,
			Data: "54.152.215.140",
		},
		{
			Kind: pantherlog.KindDomainName,
			Data: "GeneratedFindingDomainName",
		},
		{
			Kind: pantherlog.KindDomainName,
			Data: "ec2-54-152-215-140.compute-1.amazonaws.com",
		},
		{
			Kind: pantherlog.KindDomainName,
			Data: "ip-172-31-81-237.ec2.internal",
		},
		{
			Kind: KindAccountID,
			Data: "111122223333",
		},
		{
			Kind: KindAccountID,
			Data: "123456789012",
		},
		{
			Kind: KindAccountID,
			Data: "888888888888",
		},
		{
			Kind: KindARN,
			Data: "arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail",
		},
		{
			Kind: KindARN,
			Data: "arn:aws:ec2:region:111122223333:instance/",
		},
		{
			Kind: KindARN,
			Data: "arn:aws:ec2:region:111122223333:instance/i-0072230f74b3a798e",
		},
		{
			Kind: KindARN,
			Data: "arn:aws:iam::123456789012:instance-profile/EC2Dev",
		},
		{
			Kind: KindInstanceID,
			Data: "i-0072230f74b3a798e",
		},
		{
			Kind: KindInstanceID,
			Data: "i-081de1d7604b11e4a",
		},
		{
			Kind: KindTag,
			Data: "tag1:val1",
		},
	}, values)
}
