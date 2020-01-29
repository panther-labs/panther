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
	"encoding/csv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

var ALBDesc = `Application Load Balancer logs Layer 7 network logs for your application load balancer.
Reference: https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html`

const (
	albMinNumberOfColumns = 25
)

type ALB struct {
	Type                   *string            `json:"type,omitempty" validate:"oneof=http https h2 ws wss"`
	Timestamp              *timestamp.RFC3339 `json:"timestamp,omitempty" validate:"required"`
	ELB                    *string            `json:"elb,omitempty"`
	ClientIP               *string            `json:"clientIp,omitempty"`
	ClientPort             *int               `json:"clientPort,omitempty"`
	TargetIP               *string            `json:"targetIp,omitempty"`
	TargetPort             *int               `json:"targetPort,omitempty"`
	RequestProcessingTime  *float64           `json:"requestProcessingTime,omitempty"`
	TargetProcessingTime   *float64           `json:"targetProcessingTime,omitempty"`
	ResponseProcessingTime *float64           `json:"responseProcessingTime,omitempty"`
	ELBStatusCode          *int               `json:"elbStatusCode,omitempty" validate:"min=100,max=600"`
	TargetStatusCode       *int               `json:"targetStatusCode,omitempty"`
	ReceivedBytes          *int               `json:"receivedBytes,omitempty"`
	SentBytes              *int               `json:"sentBytes"`
	RequestHTTPMethod      *string            `json:"requestHttpMethod,omitempty"`
	RequestURL             *string            `json:"requestUrl,omitempty"`
	RequestHTTPVersion     *string            `json:"requestHttpVersion,omitempty"`
	UserAgent              *string            `json:"userAgent,omitempty"`
	SSLCipher              *string            `json:"sslCipher,omitempty"`
	SSLProtocol            *string            `json:"sslProtocol,omitempty"`
	TargetGroupARN         *string            `json:"targetGroupArn,omitempty"`
	TraceID                *string            `json:"traceId,omitempty"`
	DomainName             *string            `json:"domainName,omitempty"`
	ChosenCertARN          *string            `json:"chosenCertArn,omitempty"`
	MatchedRulePriority    *int               `json:"matchedRulePriority,omitempty"`
	RequestCreationTime    *timestamp.RFC3339 `json:"requestCreationTime,omitempty"`
	ActionsExecuted        []string           `json:"actionsExecuted,omitempty"`
	RedirectURL            *string            `json:"redirectUrl,omitempty"`
	ErrorReason            *string            `json:"errorReason,omitempty"`
}

// ALBParser parses AWS Application Load Balancer logs
type ALBParser struct{}

// Parse returns the parsed events or nil if parsing failed
func (p *ALBParser) Parse(log string) []interface{} {
	reader := csv.NewReader(strings.NewReader(log))
	reader.Comma = ' '

	records, err := reader.ReadAll()
	if len(records) == 0 || err != nil {
		zap.L().Debug("failed to parse the log as csv")
		return nil
	}

	// parser should only receive 1 line at a time
	record := records[0]

	if len(record) < albMinNumberOfColumns {
		zap.L().Debug("failed to parse the log as csv (wrong number of columns)")
		return nil
	}

	timeStamp, err := timestamp.Parse(time.RFC3339Nano, record[1])
	if err != nil {
		zap.L().Debug("failed to parse time", zap.Error(err))
		return nil
	}

	requestCreationTime, err := timestamp.Parse(time.RFC3339Nano, record[21])
	if err != nil {
		zap.L().Debug("failed to parse requestCreationTime", zap.Error(err))
		return nil
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
		zap.L().Debug("failed to parse request", zap.Error(err))
		return nil
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

	if err := parsers.Validator.Struct(event); err != nil {
		zap.L().Debug("failed to validate log", zap.Error(err))
		return nil
	}

	return []interface{}{event}
}

// LogType returns the log type supported by this parser
func (p *ALBParser) LogType() string {
	return "AWS.ALB"
}
