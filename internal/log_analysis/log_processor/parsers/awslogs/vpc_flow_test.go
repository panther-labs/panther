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

func TestVpcFlowLog(t *testing.T) {
	parser := &VPCFlowParser{}

	log := "2 348372346321 eni-00184058652e5a320 52.119.169.95 172.31.20.31 443 48316 6 19 7119 1573642242 1573642284 ACCEPT OK"

	expectedStartTime := time.Unix(1573642242, 0).UTC()
	expectedEndTime := time.Unix(1573642284, 0).UTC()
	expectedEvent := &VPCFlow{
		Action:      aws.String("ACCEPT"),
		Account:     aws.String("348372346321"),
		Bytes:       aws.Int(7119),
		Dstaddr:     aws.String("172.31.20.31"),
		DstPort:     aws.Int(48316),
		End:         (*timestamp.RFC3339)(&expectedEndTime),
		InterfaceID: aws.String("eni-00184058652e5a320"),
		LogStatus:   aws.String("OK"),
		Packets:     aws.Int(19),
		Protocol:    aws.Int(6),
		SourceAddr:  aws.String("52.119.169.95"),
		SrcPort:     aws.Int(443),
		Start:       (*timestamp.RFC3339)(&expectedStartTime),
		Version:     aws.Int(2),
	}

	require.Equal(t, []interface{}{expectedEvent}, parser.Parse(log))
}

func TestVpcFlowLogNoData(t *testing.T) {
	parser := &VPCFlowParser{}

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

	require.Equal(t, []interface{}{expectedEvent}, parser.Parse(log))
}

func TestVpcFlowLogHeader(t *testing.T) {
	parser := &VPCFlowParser{}
	require.Equal(t, []interface{}{}, parser.Parse(vpcFlowHeader))
}

func TestVpcFlowLogType(t *testing.T) {
	parser := &VPCFlowParser{}
	require.Equal(t, "AWS.VPCFlow", parser.LogType())
}
