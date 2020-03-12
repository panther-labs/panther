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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const (
	vpcFlowDefaultHeader  = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"                                                                                                     // nolint:lll
	vpcFlowExtendedHeader = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr pkt-dstaddr unknown-header-should-not-break" // nolint:lll
)

func TestStandardVpcFlowLog(t *testing.T) {
	log := "2 348372346321 eni-00184058652e5a320 52.119.169.95 172.31.20.31 443 48316 6 19 7119 1573642242 1573642284 ACCEPT OK extra-data-should-not-break" // nolint:lll

	expectedStartTime := time.Unix(1573642242, 0).UTC()
	expectedEndTime := time.Unix(1573642284, 0).UTC()
	expectedEvent := &VPCFlow{
		Action:      aws.String("ACCEPT"),
		AccountID:   aws.String("348372346321"),
		Bytes:       aws.Int(7119),
		DstAddr:     aws.String("172.31.20.31"),
		DstPort:     aws.Int(48316),
		End:         (*timestamp.RFC3339)(&expectedEndTime),
		InterfaceID: aws.String("eni-00184058652e5a320"),
		LogStatus:   aws.String("OK"),
		Packets:     aws.Int(19),
		Protocol:    aws.Int(6),
		SrcAddr:     aws.String("52.119.169.95"),
		SrcPort:     aws.Int(443),
		Start:       (*timestamp.RFC3339)(&expectedStartTime),
		Version:     aws.Int(2),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.VPCFlow")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedStartTime)
	expectedEvent.AppendAnyIPAddresses("172.31.20.31", "52.119.169.95")
	expectedEvent.AppendAnyAWSAccountIds("348372346321")

	checkVPCFlowLog(t, vpcFlowDefaultHeader, log, expectedEvent)
}

func TestExtendedVpcFlowLog(t *testing.T) {
	log := "3 348372346321 eni-00184058652e5a320 52.119.169.95 172.31.20.31 443 48316 6 19 7119 1573642242 1573642284 ACCEPT OK vpc-4a486c30 subnet-48998e66 i-038407d32b0f38c60 0 IPv4 76.198.154.105 172.31.88.3 extra-data-should-not-break" // nolint:lll

	expectedStartTime := time.Unix(1573642242, 0).UTC()
	expectedEndTime := time.Unix(1573642284, 0).UTC()
	expectedEvent := &VPCFlow{
		Action:      aws.String("ACCEPT"),
		AccountID:   aws.String("348372346321"),
		Bytes:       aws.Int(7119),
		DstAddr:     aws.String("172.31.20.31"),
		DstPort:     aws.Int(48316),
		End:         (*timestamp.RFC3339)(&expectedEndTime),
		InterfaceID: aws.String("eni-00184058652e5a320"),
		LogStatus:   aws.String("OK"),
		Packets:     aws.Int(19),
		Protocol:    aws.Int(6),
		SrcAddr:     aws.String("52.119.169.95"),
		SrcPort:     aws.Int(443),
		Start:       (*timestamp.RFC3339)(&expectedStartTime),
		Version:     aws.Int(3),

		VpcID:         aws.String("vpc-4a486c30"),
		SubNetID:      aws.String("subnet-48998e66"),
		InstanceID:    aws.String("i-038407d32b0f38c60"),
		TCPFlags:      aws.Int(0),
		Type:          aws.String("IPv4"),
		PacketSrcAddr: aws.String("76.198.154.105"),
		PacketDstAddr: aws.String("172.31.88.3"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.VPCFlow")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedStartTime)
	expectedEvent.AppendAnyIPAddresses("172.31.20.31", "52.119.169.95", "76.198.154.105", "172.31.88.3")
	expectedEvent.AppendAnyAWSAccountIds("348372346321")
	expectedEvent.AppendAnyAWSInstanceIds("i-038407d32b0f38c60")

	checkVPCFlowLog(t, vpcFlowExtendedHeader, log, expectedEvent)
}

func TestVpcFlowLogNoData(t *testing.T) {
	log := "2 unknown eni-0608192d5c498fbcd - - - - - - - 1538696170 1538696308 - NODATA"

	expectedStartTime := time.Unix(1538696170, 0).UTC()
	expectedEndTime := time.Unix(1538696308, 0).UTC()
	expectedEvent := &VPCFlow{
		Version:     aws.Int(2),
		InterfaceID: aws.String("eni-0608192d5c498fbcd"),
		Start:       (*timestamp.RFC3339)(&expectedStartTime),
		End:         (*timestamp.RFC3339)(&expectedEndTime),
		LogStatus:   aws.String("NODATA"),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.VPCFlow")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedStartTime)

	checkVPCFlowLog(t, vpcFlowDefaultHeader, log, expectedEvent)
}

func TestVpcFlowLogHeader(t *testing.T) {
	parser := &VPCFlowParser{}
	require.Equal(t, []*parsers.PantherLog{}, parser.Parse(vpcFlowDefaultHeader))
}

func TestVpcFlowLogType(t *testing.T) {
	parser := &VPCFlowParser{}
	require.Equal(t, "AWS.VPCFlow", parser.LogType())
}

func checkVPCFlowLog(t *testing.T, header, log string, expectedEvent *VPCFlow) {
	parser := &VPCFlowParser{}
	parser.Parse(header)
	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
