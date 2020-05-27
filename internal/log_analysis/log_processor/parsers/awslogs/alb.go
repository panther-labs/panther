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
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/csvstream"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeALB = "AWS.ALB"

var ALBDesc = `Application Load Balancer logs Layer 7 network logs for your application load balancer.
Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html`

const (
	albMinNumberOfColumns = 25
)

// nolint:lll
type ALB struct {
	Type                   *string            `json:"type,omitempty" validate:"oneof=http https h2 ws wss" description:"The type of request or connection."`
	Timestamp              *timestamp.RFC3339 `json:"timestamp,omitempty" validate:"required" description:"The time when the load balancer generated a response to the client (UTC). For WebSockets, this is the time when the connection is closed."`
	ELB                    *string            `json:"elb,omitempty" description:"The resource ID of the load balancer. If you are parsing access log entries, note that resources IDs can contain forward slashes (/)."`
	ClientIP               *string            `json:"clientIp,omitempty" description:"The IP address of the requesting client."`
	ClientPort             *int               `json:"clientPort,omitempty" description:"The port of the requesting client."`
	TargetIP               *string            `json:"targetIp,omitempty" description:"The IP address of the target that processed this request."`
	TargetPort             *int               `json:"targetPort,omitempty" description:"The port of the target that processed this request."`
	RequestProcessingTime  *float64           `json:"requestProcessingTime,omitempty" description:"The total time elapsed (in seconds, with millisecond precision) from the time the load balancer received the request until the time it sent it to a target. This value is set to -1 if the load balancer can't dispatch the request to a target. This can happen if the target closes the connection before the idle timeout or if the client sends a malformed request. This value can also be set to -1 if the registered target does not respond before the idle timeout."`
	TargetProcessingTime   *float64           `json:"targetProcessingTime,omitempty" description:"The total time elapsed (in seconds, with millisecond precision) from the time the load balancer sent the request to a target until the target started to send the response headers. This value is set to -1 if the load balancer can't dispatch the request to a target. This can happen if the target closes the connection before the idle timeout or if the client sends a malformed request. This value can also be set to -1 if the registered target does not respond before the idle timeout."`
	ResponseProcessingTime *float64           `json:"responseProcessingTime,omitempty" description:"The total time elapsed (in seconds, with millisecond precision) from the time the load balancer received the response header from the target until it started to send the response to the client. This includes both the queuing time at the load balancer and the connection acquisition time from the load balancer to the client. This value is set to -1 if the load balancer can't send the request to a target. This can happen if the target closes the connection before the idle timeout or if the client sends a malformed request."`
	ELBStatusCode          *int               `json:"elbStatusCode,omitempty" validate:"min=100,max=600" description:"The status code of the response from the load balancer."`
	TargetStatusCode       *int               `json:"targetStatusCode,omitempty" description:"The status code of the response from the target. This value is recorded only if a connection was established to the target and the target sent a response."`
	ReceivedBytes          *int               `json:"receivedBytes,omitempty" description:"The size of the request, in bytes, received from the client (requester). For HTTP requests, this includes the headers. For WebSockets, this is the total number of bytes received from the client on the connection."`
	SentBytes              *int               `json:"sentBytes" description:"The size of the response, in bytes, sent to the client (requester). For HTTP requests, this includes the headers. For WebSockets, this is the total number of bytes sent to the client on the connection."`
	RequestHTTPMethod      *string            `json:"requestHttpMethod,omitempty" description:"The HTTP method parsed from the request."`
	RequestURL             *string            `json:"requestUrl,omitempty" description:"The HTTP URL parsed from the request."`
	RequestHTTPVersion     *string            `json:"requestHttpVersion,omitempty" description:"The HTTP version parsed from the request."`
	UserAgent              *string            `json:"userAgent,omitempty" description:"A User-Agent string that identifies the client that originated the request. The string consists of one or more product identifiers, product[/version]. If the string is longer than 8 KB, it is truncated."`
	SSLCipher              *string            `json:"sslCipher,omitempty" description:"[HTTPS listener] The SSL cipher. This value is set to NULL if the listener is not an HTTPS listener."`
	SSLProtocol            *string            `json:"sslProtocol,omitempty" description:"[HTTPS listener] The SSL protocol. This value is set to NULL if the listener is not an HTTPS listener."`
	TargetGroupARN         *string            `json:"targetGroupArn,omitempty" description:"The Amazon Resource Name (ARN) of the target group."`
	TraceID                *string            `json:"traceId,omitempty" description:"The contents of the X-Amzn-Trace-Id header."`
	DomainName             *string            `json:"domainName,omitempty" description:"[HTTPS listener] The SNI domain provided by the client during the TLS handshake. This value is set to NULL if the client doesn't support SNI or the domain doesn't match a certificate and the default certificate is presented to the client."`
	ChosenCertARN          *string            `json:"chosenCertArn,omitempty" description:"[HTTPS listener] The ARN of the certificate presented to the client. This value is set to session-reused if the session is reused. This value is set to NULL if the listener is not an HTTPS listener."`
	MatchedRulePriority    *int               `json:"matchedRulePriority,omitempty" description:"The priority value of the rule that matched the request. If a rule matched, this is a value from 1 to 50,000. If no rule matched and the default action was taken, this value is set to 0. If an error occurs during rules evaluation, it is set to -1. For any other error, it is set to NULL."`
	RequestCreationTime    *timestamp.RFC3339 `json:"requestCreationTime,omitempty" description:"The time when the load balancer received the request from the client."`
	ActionsExecuted        []string           `json:"actionsExecuted,omitempty" description:"The actions taken when processing the request. This value is a comma-separated list that can include the values described in Actions Taken. If no action was taken, such as for a malformed request, this value is set to NULL."`
	RedirectURL            *string            `json:"redirectUrl,omitempty" description:"The URL of the redirect target for the location header of the HTTP response. If no redirect actions were taken, this value is set to NULL."`
	ErrorReason            *string            `json:"errorReason,omitempty" description:"The error reason code. If the request failed, this is one of the error codes described in Error Reason Codes. If the actions taken do not include an authenticate action or the target is not a Lambda function, this value is set to NULL."`

	// NOTE: added to end of struct to allow expansion later
	AWSPantherLog
}

// ALBParser parses AWS Application Load Balancer logs
type ALBParser struct {
	CSVReader *csvstream.StreamingCSVReader
}

var _ parsers.LogParser = (*ALBParser)(nil)

func (p *ALBParser) New() parsers.LogParser {
	reader := csvstream.NewStreamingCSVReader()
	// non-default settings
	reader.CVSReader.Comma = ' '
	return &ALBParser{
		CSVReader: reader,
	}
}

// Parse returns the parsed events or nil if parsing failed
func (p *ALBParser) Parse(log string) ([]*parsers.PantherLog, error) {
	record, err := p.CSVReader.Parse(log)
	if err != nil {
		return nil, err
	}

	if len(record) < albMinNumberOfColumns {
		return nil, errors.New("invalid number of columns")
	}

	timeStamp, err := timestamp.Parse(time.RFC3339Nano, record[1])
	if err != nil {
		return nil, err
	}

	requestCreationTime, err := timestamp.Parse(time.RFC3339Nano, record[21])
	if err != nil {
		return nil, err
	}

	var clientIPPort, targetIPPort []string
	clientIPPort = strings.Split(record[3], ":")
	if len(clientIPPort) != 2 {
		clientIPPort = []string{record[3], "-"}
	}
	targetIPPort = strings.Split(record[4], ":")
	if len(targetIPPort) != 2 {
		targetIPPort = []string{record[4], "-"}
	}

	requestItems := strings.Split(record[12], " ")

	if len(requestItems) != 3 {
		return nil, errors.New("invalid record")
	}

	event := &ALB{
		Type:                   parsers.CsvStringToPointer(record[0]),
		Timestamp:              &timeStamp,
		ELB:                    parsers.CsvStringToPointer(record[2]),
		ClientIP:               parsers.CsvStringToPointer(clientIPPort[0]),
		ClientPort:             parsers.CsvStringToIntPointer(clientIPPort[1]),
		TargetIP:               parsers.CsvStringToPointer(targetIPPort[0]),
		TargetPort:             parsers.CsvStringToIntPointer(targetIPPort[1]),
		RequestProcessingTime:  parsers.CsvStringToFloat64Pointer(record[5]),
		TargetProcessingTime:   parsers.CsvStringToFloat64Pointer(record[6]),
		ResponseProcessingTime: parsers.CsvStringToFloat64Pointer(record[7]),
		ELBStatusCode:          parsers.CsvStringToIntPointer(record[8]),
		TargetStatusCode:       parsers.CsvStringToIntPointer(record[9]),
		ReceivedBytes:          parsers.CsvStringToIntPointer(record[10]),
		SentBytes:              parsers.CsvStringToIntPointer(record[11]),
		RequestHTTPMethod:      parsers.CsvStringToPointer(requestItems[0]),
		RequestURL:             parsers.CsvStringToPointer(requestItems[1]),
		RequestHTTPVersion:     parsers.CsvStringToPointer(requestItems[2]),
		UserAgent:              parsers.CsvStringToPointer(record[13]),
		SSLCipher:              parsers.CsvStringToPointer(record[14]),
		SSLProtocol:            parsers.CsvStringToPointer(record[15]),
		TargetGroupARN:         parsers.CsvStringToPointer(record[16]),
		TraceID:                parsers.CsvStringToPointer(record[17]),
		DomainName:             parsers.CsvStringToPointer(record[18]),
		ChosenCertARN:          parsers.CsvStringToPointer(record[19]),
		MatchedRulePriority:    parsers.CsvStringToIntPointer(record[20]),
		RequestCreationTime:    &requestCreationTime,
		ActionsExecuted:        parsers.CsvStringToArray(record[22]),
		RedirectURL:            parsers.CsvStringToPointer(record[23]),
		ErrorReason:            parsers.CsvStringToPointer(record[24]),
	}

	event.updatePantherFields(p)

	if err := parsers.Validator.Struct(event); err != nil {
		return nil, err
	}

	return event.Logs(), nil
}

// LogType returns the log type supported by this parser
func (p *ALBParser) LogType() string {
	return TypeALB
}

func (event *ALB) updatePantherFields(p *ALBParser) {
	event.SetCoreFields(p.LogType(), event.Timestamp, event)
	event.AppendAnyIPAddressPtr(event.ClientIP)
	event.AppendAnyIPAddressPtr(event.TargetIP)
	event.AppendAnyDomainNamePtrs(event.DomainName)
	event.AppendAnyAWSARNPtrs(event.ChosenCertARN, event.TargetGroupARN)
}
