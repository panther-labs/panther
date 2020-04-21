package suricatalogs

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

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/numerics"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestAnomaly(t *testing.T) {
	//nolint:lll
	log := `{"timestamp": "2015-10-22T11:17:43.787396+0000", "flow_id": 1736252438606144, "pcap_cnt": 1803045, "event_type": "anomaly", "src_ip": "192.168.88.25", "src_port": 32483, "dest_ip": "192.168.2.22", "dest_port": 59050, "proto": "006", "community_id": "1:N83Uv4ioTSH1OQtnSJxvUaj9jpc=", "packet": "AAd8GmGDANDJpcktCABFAAAoWqcAAEAGRKnAqFgZwKg=", "packet_info": {"linktype": 1}, "anomaly": {"type": "stream", "event": "stream.rst_but_no_session"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`
	expectedTime := time.Date(2015, 10, 22, 11, 17, 43, 787396000, time.UTC)
	expectedEvent := &Anomaly{
		Timestamp:   (*timestamp.SuricataTimestamp)(&expectedTime),
		FlowID:      aws.Int(1736252438606144),
		PcapCnt:     aws.Int(1803045),
		EventType:   aws.String("anomaly"),
		SrcIP:       aws.String("192.168.88.25"),
		SrcPort:     aws.Uint16(32483),
		DestIP:      aws.String("192.168.2.22"),
		DestPort:    aws.Uint16(59050),
		Proto:       (*numerics.Integer)(aws.Int(6)),
		CommunityID: aws.String("1:N83Uv4ioTSH1OQtnSJxvUaj9jpc="),
		Packet:      aws.String("AAd8GmGDANDJpcktCABFAAAoWqcAAEAGRKnAqFgZwKg="),
		PacketInfo: &AnomalyPacketInfo{
			Linktype: aws.Int(1),
		},
		Anomaly: &AnomalyDetails{
			Type:  aws.String("stream"),
			Event: aws.String("stream.rst_but_no_session"),
		},
		PcapFilename: aws.String("/pcaps/4SICS-GeekLounge-151022.pcap"),
	}
	expectedEvent.PantherLogType = aws.String("Suricata.Anomaly")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.SetEvent(expectedEvent)
	expectedEvent.AppendAnyIPAddress("192.168.88.25")
	expectedEvent.AppendAnyIPAddress("192.168.2.22")

	parser := (&AnomalyParser{}).New()
	events, err := parser.Parse(log)
	testutil.EqualPantherLog(t, expectedEvent.Log(), events, err)
}

func TestAnomalyType(t *testing.T) {
	parser := &AnomalyParser{}
	require.Equal(t, "Suricata.Anomaly", parser.LogType())
}
