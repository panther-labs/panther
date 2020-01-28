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

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/pkg/extract"
)

func TestAWSExtractor(t *testing.T) {
	event := parsers.PantherLog{}
	// add interesting fragments as new extractions are implemented
	json := `
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
	expectedEvent := parsers.PantherLog{}
	expectedEvent.AppendAnyAWSARNs("arn:aws:iam::123456789012:instance-profile/EC2Dev",
		"arn:aws:cloudtrail:us-west-2:888888888888:trail/panther-lab-cloudtrail")
	expectedEvent.AppendAnyAWSInstanceIds("i-081de1d7604b11e4a")
	expectedEvent.AppendAnyAWSAccountIds("123456789012")
	expectedEvent.AppendAnyIPAddresses("54.152.215.140", "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		"172.31.81.237", "151.80.19.228")
	expectedEvent.AppendAnyAWSTags("tag1:val1")
	expectedEvent.AppendAnyDomainNames("ec2-54-152-215-140.compute-1.amazonaws.com", "GeneratedFindingDomainName",
		"ip-172-31-81-237.ec2.internal")

	result := gjson.Parse(json)
	extract.Extract(result, NewAWSExtractor(&event))

	require.Equal(t, expectedEvent, event)
}
