package umbrellalogs

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
	"strconv"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/csvstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

type ProxyParser struct {
	*csvstream.StreamingCSVReader
}

func NewProxyParser() *ProxyParser {
	return &ProxyParser{
		StreamingCSVReader: csvstream.NewStreamingCSVReader(),
	}
}

var _ parsers.LogParser = (*ProxyParser)(nil)

func (p *ProxyParser) New() parsers.LogParser {
	return NewProxyParser()
}

func (p *ProxyParser) LogType() string {
	return TypeProxy
}

func (p *ProxyParser) Parse(log string) ([]*parsers.PantherLog, error) {
	row, err := p.StreamingCSVReader.Parse(log)
	if err != nil {
		return nil, err
	}

	event := Proxy{}
	if err := event.setRow(row); err != nil {
		return nil, err
	}
	event.updatePantherFields(&event.PantherLog)
	return event.Logs(), nil
}

// nolint:lll
type Proxy struct {
	Timestamp        timestamp.RFC3339 `json:"timestamp" description:"The timestamp of the request transaction in UTC (2015-01-16 17:48:41)."`
	Identity         string            `json:"identity,omitempty" description:"The first identity that matched the request."`
	Identities       []string          `json:"identities,omitempty" description:"Which identities, in order of granularity, made the request through the intelligent proxy."`
	InternalIP       string            `json:"internalIp,omitempty" description:"The internal IP address of the computer making the request."`
	ExternalIP       string            `json:"externalIp,omitempty" description:"The egress IP address of the network where the request originated."`
	DestinationIP    string            `json:"destinationIp,omitempty" description:"The destination IP address of the request."`
	ContentType      string            `json:"contentType,omitempty" description:"The type of web content, typically text/html."`
	Verdict          string            `json:"verdict,omitempty" description:"Whether the destination was blocked or allowed."`
	URL              string            `json:"url,omitempty" description:"The URL requested."`
	Referer          string            `json:"referrer,omitempty" description:"The referring domain or URL."`
	UserAgent        string            `json:"userAgent,omitempty" description:"The browser agent that made the request."`
	StatusCode       int32             `json:"statusCode,omitempty" description:"The HTTP status code; should always be 200 or 201."`
	RequestSize      int64             `json:"requestSize,omitempty" description:"Request size in bytes."`
	ResponseSize     int64             `json:"responseSize,omitempty" description:"Response size in bytes."`
	ResponseBodySize int64             `json:"responseBodySize,omitempty" description:"Response body size in bytes."`
	SHA              string            `json:"sha,omitempty" description:"SHA256 hex digest of the response content."`
	Categories       []string          `json:"categories,omitempty" description:"The security categories for this request, such as Malware."`
	AVDetections     []string          `json:"avDetections,omitempty" description:"The detection name according to the antivirus engine used in file inspection."`
	PUAs             []string          `json:"puas,omitempty" description:"A list of all potentially unwanted application (PUA) results for the proxied file as returned by the antivirus scanner."`
	AMPDisposition   string            `json:"ampDisposition,omitempty" description:"The status of the files proxied and scanned by Cisco Advanced Malware Protection (AMP) as part of the Umbrella File Inspection feature; can be Clean, Malicious or Unknown."`
	AMPMalwareName   string            `json:"ampMalwareName,omitempty" description:"If Malicious, the name of the malware according to AMP."`
	AMPScore         string            `json:"ampScore,omitempty" description:"The score of the malware from AMP. This field is not currently used and will be blank."`
	// V3
	IdentityType string `json:"identityType,omitempty" description:"The type of identity that made the request. For example, Roaming Computer, Network, and so on."`
	// V4
	BlockedCategories []string `json:"blockedCategories,omitempty" description:"The categories that resulted in the destination being blocked. Available in version 4 and above."`

	parsers.PantherLog
}

func (event *Proxy) setRow(row []string) error {
	const (
		numFieldsProxy   = 22
		numFieldsProxyV3 = 23
		numFieldsProxyV4 = 24
	)
	if len(row) < numFieldsProxy {
		return errors.New("invalid number of fields")
	}
	// Be verbose to have a 1:1 mapping of field names without overhead (stack allocated struct + bounds check elision)
	// This avoids weird variable names and mistakes are easily spotted
	fields := struct {
		Timestamp        string
		StatusCode       string
		RequestSize      string
		ResponseSize     string
		ResponseBodySize string
	}{
		Timestamp:        row[0],
		StatusCode:       row[11],
		RequestSize:      row[12],
		ResponseSize:     row[13],
		ResponseBodySize: row[14],
	}
	tm, err := time.ParseInLocation(layoutUmbrellaTimestamp, fields.Timestamp, time.UTC)
	if err != nil {
		return err
	}
	// Docs state that the field is always "200" or "201"
	// Use this as a way to detect invalid CSV rows with similar size
	var statusCode int32
	switch fields.StatusCode {
	case "200":
		statusCode = 200
	case "201":
		statusCode = 201
	default:
		return errors.Errorf("invalid status code field %q", row[11])
	}
	// Avoid overflows by using strconv.ParseInt bitSize argument
	var (
		reqSize, _  = strconv.ParseInt(fields.RequestSize, 10, 64)
		respSize, _ = strconv.ParseInt(fields.ResponseSize, 10, 64)
		bodySize, _ = strconv.ParseInt(fields.ResponseBodySize, 10, 64)
	)

	*event = Proxy{
		Timestamp:        timestamp.RFC3339(tm),
		Identity:         row[1],
		Identities:       parseList(row[2]),
		InternalIP:       row[3],
		ExternalIP:       row[4],
		DestinationIP:    row[5],
		ContentType:      row[6],
		Verdict:          row[7],
		URL:              row[8],
		Referer:          row[9],
		UserAgent:        row[10],
		StatusCode:       statusCode,
		RequestSize:      reqSize,
		ResponseSize:     respSize,
		ResponseBodySize: bodySize,
		SHA:              row[15],
		Categories:       parseList(row[16]),
		AVDetections:     parseList(row[17]),
		PUAs:             parseList(row[18]),
		AMPDisposition:   row[19],
		AMPMalwareName:   row[20],
		AMPScore:         row[21],
	}
	// Handle V3
	if len(row) >= numFieldsProxyV3 {
		event.IdentityType = row[22]
		// Handle V4
		if len(row) >= numFieldsProxyV4 {
			event.BlockedCategories = parseList(row[23])
		}
	}
	return nil
}

func (event *Proxy) updatePantherFields(p *parsers.PantherLog) {
	p.SetCoreFields(TypeProxy, &event.Timestamp, event)
	p.AppendAnyIPAddress(event.InternalIP)
	p.AppendAnyIPAddress(event.ExternalIP)
	p.AppendAnyIPAddress(event.DestinationIP)
	if event.SHA != "" {
		p.AppendAnySHA256Hashes(event.SHA)
	}
}
