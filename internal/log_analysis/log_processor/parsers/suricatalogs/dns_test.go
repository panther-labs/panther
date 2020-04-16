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

func TestDNSQuery(t *testing.T) {
	//nolint:lll
	log := `{"timestamp": "2015-10-22T06:31:06.520370+0000", "flow_id": 188564141437106, "pcap_cnt": 229108, "event_type": "dns", "src_ip": "192.168.89.2", "src_port": 27864, "dest_ip": "8.8.8.8", "dest_port": 53, "proto": "017", "community_id": "1:2lDamoPjfWU3FGYJXWeXwZwtza4=", "dns": {"type": "query", "id": 62705, "rrname": "localhost", "rrtype": "A", "tx_id": 0}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`

	expectedTime := time.Date(2015, 10, 22, 6, 31, 6, 520370000, time.UTC)

	expectedEvent := &DNS{
		Timestamp:   (*timestamp.SuricataTimestamp)(&expectedTime),
		FlowID:      aws.Int(188564141437106),
		PcapCnt:     aws.Int(229108),
		EventType:   aws.String("dns"),
		SrcIP:       aws.String("192.168.89.2"),
		SrcPort:     aws.Uint16(27864),
		DestIP:      aws.String("8.8.8.8"),
		DestPort:    aws.Uint16(53),
		Proto:       (*numerics.Integer)(aws.Int(17)),
		CommunityID: aws.String("1:2lDamoPjfWU3FGYJXWeXwZwtza4="),
		DNS: &DNSDetails{
			Type:   aws.String("query"),
			ID:     aws.Int(62705),
			Rrname: aws.String("localhost"),
			Rrtype: aws.String("A"),
			TxID:   aws.Int(0),
		},
		PcapFilename: aws.String("/pcaps/4SICS-GeekLounge-151022.pcap"),
	}
	expectedEvent.SetCoreFields("Suricata.DNS", (*timestamp.RFC3339)(&expectedTime), expectedEvent)
	expectedEvent.AppendAnyIPAddress("192.168.89.2")
	expectedEvent.AppendAnyIPAddress("8.8.8.8")
	expectedEvent.AppendAnyDomainNames("localhost")
	parser := (&DNSParser{}).New()

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}

func TestDNSAnswerNoError(t *testing.T) {
	//nolint:lll
	log := `{"timestamp": "2015-10-22T06:33:45.364388+0000", "flow_id": 1650515353776555, "pcap_cnt": 230388, "event_type": "dns", "src_ip": "192.168.88.1", "src_port": 53, "dest_ip": "192.168.88.61", "dest_port": 949, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"type": "answer", "id":16000, "flags":"8180", "qr":true, "rd":true,"ra":true, "rcode":"NOERROR","rrname": "twitter.com", "rrtype":"A", "ttl":8,"rdata": "199.16.156.6"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`

	expectedTime := time.Date(2015, 10, 22, 6, 33, 45, 364388000, time.UTC)

	expectedEvent := &DNS{
		Timestamp:   (*timestamp.SuricataTimestamp)(&expectedTime),
		FlowID:      aws.Int(1650515353776555),
		PcapCnt:     aws.Int(230388),
		EventType:   aws.String("dns"),
		SrcIP:       aws.String("192.168.88.1"),
		SrcPort:     aws.Uint16(53),
		DestIP:      aws.String("192.168.88.61"),
		DestPort:    aws.Uint16(949),
		Proto:       (*numerics.Integer)(aws.Int(17)),
		CommunityID: aws.String("1:41V2KTo0JgeGFmVA0p5LUTyRyvA="),
		DNS: &DNSDetails{
			Flags:  aws.String("8180"),
			Qr:     aws.Bool(true),
			Rd:     aws.Bool(true),
			Ra:     aws.Bool(true),
			Rrname: aws.String("twitter.com"),
			RData:  aws.String("199.16.156.6"),
			TTL:    aws.Int(8),
			Rcode:  aws.String("NOERROR"),
			Rrtype: aws.String("A"),
			Type:   aws.String("answer"),
			ID:     aws.Int(16000),
		},
		PcapFilename: aws.String("/pcaps/4SICS-GeekLounge-151022.pcap"),
	}
	expectedEvent.SetCoreFields("Suricata.DNS", (*timestamp.RFC3339)(&expectedTime), expectedEvent)
	expectedEvent.AppendAnyIPAddress("192.168.88.1")
	expectedEvent.AppendAnyIPAddress("192.168.88.61")
	expectedEvent.AppendAnyIPAddress("199.16.156.6")
	expectedEvent.AppendAnyDomainNames("twitter.com")
	parser := (&DNSParser{}).New()

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}

func TestDNSAnswerRefused(t *testing.T) {
	//nolint:lll
	log := `{"timestamp": "2015-10-22T06:33:45.364388+0000", "flow_id": 1650515353776555, "pcap_cnt": 230388, "event_type": "dns", "src_ip": "192.168.88.1", "src_port": 53, "dest_ip": "192.168.88.61", "dest_port": 949, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"version": 2, "type": "answer", "id": 48966, "flags": "8185", "qr": true, "rd": true, "ra": true, "rrname": "time.nist.gov", "rrtype": "A", "rcode": "REFUSED"}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`

	expectedTime := time.Date(2015, 10, 22, 6, 33, 45, 364388000, time.UTC)

	expectedEvent := &DNS{
		Timestamp:   (*timestamp.SuricataTimestamp)(&expectedTime),
		FlowID:      aws.Int(1650515353776555),
		PcapCnt:     aws.Int(230388),
		EventType:   aws.String("dns"),
		SrcIP:       aws.String("192.168.88.1"),
		SrcPort:     aws.Uint16(53),
		DestIP:      aws.String("192.168.88.61"),
		DestPort:    aws.Uint16(949),
		Proto:       (*numerics.Integer)(aws.Int(17)),
		CommunityID: aws.String("1:41V2KTo0JgeGFmVA0p5LUTyRyvA="),
		DNS: &DNSDetails{
			Version: aws.Int(2),
			Flags:   aws.String("8185"),
			Qr:      aws.Bool(true),
			Rd:      aws.Bool(true),
			Ra:      aws.Bool(true),
			Rrname:  aws.String("time.nist.gov"),
			Rcode:   aws.String("REFUSED"),
			Rrtype:  aws.String("A"),
			Type:    aws.String("answer"),
			ID:      aws.Int(48966),
		},
		PcapFilename: aws.String("/pcaps/4SICS-GeekLounge-151022.pcap"),
	}
	expectedEvent.SetCoreFields("Suricata.DNS", (*timestamp.RFC3339)(&expectedTime), expectedEvent)
	expectedEvent.AppendAnyIPAddress("192.168.88.1")
	expectedEvent.AppendAnyIPAddress("192.168.88.61")
	expectedEvent.AppendAnyDomainNames("time.nist.gov")
	parser := (&DNSParser{}).New()

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}

func TestDNSDetailedFormat(t *testing.T) {
	// Example taken from https://github.com/OISF/suricata/blob/master/doc/userguide/output/eve/eve-json-format.rst#event-type-dns
	//nolint:lll
	log := `{"timestamp": "2015-10-22T06:33:45.364388+0000", "flow_id": 1650515353776555, "pcap_cnt": 230388, "event_type": "dns", "src_ip": "192.168.88.1", "src_port": 53, "dest_ip": "192.168.88.61", "dest_port": 949, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"version": 2, "type": "answer", "id": 45444, "flags": "8180", "qr": true,"rd": true, "ra": true, "rcode": "NOERROR", "answers": [{"rrname": "suricata-ids.org", "rrtype": "A", "ttl": 10, "rdata": "192.0.78.24"},{"rrname": "suricata-ids.org", "rrtype": "A", "ttl": 10, "rdata": "192.0.78.25"},{"rrname": "suricata-ids-aaaa.org", "rrtype": "AAAA", "ttl": 10, "rdata": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},{"rrname": "suricata-ids-cname.org", "rrtype": "CNAME", "ttl": 10, "rdata": "foo.suricata-ids.org"},{"rrname": "suricata-ids-txt.org", "rrtype": "TXT", "ttl": 10, "rdata": "Test Text"},{"rrname": "suricata-ids-mx.org", "rrtype": "MX", "ttl": 10, "rdata": "mail.server"}]}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`

	expectedTime := time.Date(2015, 10, 22, 6, 33, 45, 364388000, time.UTC)

	expectedEvent := &DNS{
		Timestamp:   (*timestamp.SuricataTimestamp)(&expectedTime),
		FlowID:      aws.Int(1650515353776555),
		PcapCnt:     aws.Int(230388),
		EventType:   aws.String("dns"),
		SrcIP:       aws.String("192.168.88.1"),
		SrcPort:     aws.Uint16(53),
		DestIP:      aws.String("192.168.88.61"),
		DestPort:    aws.Uint16(949),
		Proto:       (*numerics.Integer)(aws.Int(17)),
		CommunityID: aws.String("1:41V2KTo0JgeGFmVA0p5LUTyRyvA="),
		DNS: &DNSDetails{
			Version: aws.Int(2),
			ID:      aws.Int(45444),
			Flags:   aws.String("8180"),
			Qr:      aws.Bool(true),
			Rd:      aws.Bool(true),
			Ra:      aws.Bool(true),
			Rcode:   aws.String("NOERROR"),
			Type:    aws.String("answer"),
			Answers: []DNSDetailsAnswers{
				{
					Rrname: aws.String("suricata-ids.org"),
					Rrtype: aws.String("A"),
					TTL:    aws.Int(10),
					Rdata:  aws.String("192.0.78.24"),
				},
				{
					Rrname: aws.String("suricata-ids.org"),
					Rrtype: aws.String("A"),
					TTL:    aws.Int(10),
					Rdata:  aws.String("192.0.78.25"),
				},
				{
					Rrname: aws.String("suricata-ids-aaaa.org"),
					Rrtype: aws.String("AAAA"),
					TTL:    aws.Int(10),
					Rdata:  aws.String("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
				},
				{
					Rrname: aws.String("suricata-ids-cname.org"),
					Rrtype: aws.String("CNAME"),
					TTL:    aws.Int(10),
					Rdata:  aws.String("foo.suricata-ids.org"),
				},
				{
					Rrname: aws.String("suricata-ids-txt.org"),
					Rrtype: aws.String("TXT"),
					TTL:    aws.Int(10),
					Rdata:  aws.String("Test Text"),
				},
				{
					Rrname: aws.String("suricata-ids-mx.org"),
					Rrtype: aws.String("MX"),
					TTL:    aws.Int(10),
					Rdata:  aws.String("mail.server"),
				},
			},
		},
		PcapFilename: aws.String("/pcaps/4SICS-GeekLounge-151022.pcap"),
	}
	expectedEvent.SetCoreFields("Suricata.DNS", (*timestamp.RFC3339)(&expectedTime), expectedEvent)
	expectedEvent.AppendAnyIPAddress("192.168.88.1")
	expectedEvent.AppendAnyIPAddress("192.168.88.61")
	expectedEvent.AppendAnyIPAddress("192.0.78.24")
	expectedEvent.AppendAnyIPAddress("192.0.78.25")
	expectedEvent.AppendAnyIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	expectedEvent.AppendAnyDomainNames(
		"suricata-ids.org",
		"suricata-ids-aaaa.org",
		"suricata-ids-cname.org",
		"suricata-ids-txt.org",
		"suricata-ids-mx.org")
	parser := (&DNSParser{}).New()

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}

func TestDNSGroupedFormat(t *testing.T) {
	// Example taken from https://github.com/OISF/suricata/blob/master/doc/userguide/output/eve/eve-json-format.rst#event-type-dns
	//nolint:lll
	log := `{"timestamp": "2015-10-22T06:33:45.364388+0000", "flow_id": 1650515353776555, "pcap_cnt": 230388, "event_type": "dns", "src_ip": "192.168.88.1", "src_port": 53, "dest_ip": "192.168.88.61", "dest_port": 949, "proto": "017", "community_id": "1:41V2KTo0JgeGFmVA0p5LUTyRyvA=", "dns": {"version": 2, "type": "answer", "id": 18523, "flags": "8180", "qr": true,"rd": true, "ra": true, "rcode": "NOERROR", "grouped": {"A": ["192.0.78.24", "192.0.78.25"], "CNAME": ["suricata-ids.org"]}}, "pcap_filename": "/pcaps/4SICS-GeekLounge-151022.pcap"}`

	expectedTime := time.Date(2015, 10, 22, 6, 33, 45, 364388000, time.UTC)

	expectedEvent := &DNS{
		Timestamp:   (*timestamp.SuricataTimestamp)(&expectedTime),
		FlowID:      aws.Int(1650515353776555),
		PcapCnt:     aws.Int(230388),
		EventType:   aws.String("dns"),
		SrcIP:       aws.String("192.168.88.1"),
		SrcPort:     aws.Uint16(53),
		DestIP:      aws.String("192.168.88.61"),
		DestPort:    aws.Uint16(949),
		Proto:       (*numerics.Integer)(aws.Int(17)),
		CommunityID: aws.String("1:41V2KTo0JgeGFmVA0p5LUTyRyvA="),
		DNS: &DNSDetails{
			Version: aws.Int(2),
			ID:      aws.Int(18523),
			Flags:   aws.String("8180"),
			Qr:      aws.Bool(true),
			Rd:      aws.Bool(true),
			Ra:      aws.Bool(true),
			Rcode:   aws.String("NOERROR"),
			Type:    aws.String("answer"),
			Grouped: &DNSDetailsGrouped{
				A:     []string{"192.0.78.24", "192.0.78.25"},
				Cname: []string{"suricata-ids.org"},
			},
		},
		PcapFilename: aws.String("/pcaps/4SICS-GeekLounge-151022.pcap"),
	}
	expectedEvent.SetCoreFields("Suricata.DNS", (*timestamp.RFC3339)(&expectedTime), expectedEvent)
	expectedEvent.AppendAnyIPAddress("192.168.88.1")
	expectedEvent.AppendAnyIPAddress("192.168.88.61")
	expectedEvent.AppendAnyIPAddress("192.0.78.24")
	expectedEvent.AppendAnyIPAddress("192.0.78.25")
	expectedEvent.AppendAnyDomainNames("suricata-ids.org")
	parser := (&DNSParser{}).New()

	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}

func TestDNSType(t *testing.T) {
	parser := &DNSParser{}
	require.Equal(t, "Suricata.DNS", parser.LogType())
}
