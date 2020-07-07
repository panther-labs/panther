package juniperlogs

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
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

const TypeSecurity = `Juniper.Security`

type SecurityParser struct {
	timestampParser
}

func NewSecurityParser() *SecurityParser {
	return &SecurityParser{
		timestampParser: timestampParser{
			Now: time.Now(),
		},
	}
}

var _ parsers.LogParser = (*SecurityParser)(nil)

func (p *SecurityParser) New() parsers.LogParser {
	return NewSecurityParser()
}
func (p *SecurityParser) LogType() string {
	return TypeSecurity
}

func (p *SecurityParser) Parse(log string) ([]*parsers.PantherLog, error) {
	match := rxSecurity.FindStringSubmatch(log)
	const numMatches = 7
	if len(match) != numMatches {
		return nil, errors.New(`invalid log line`)
	}
	fields := struct {
		Timestamp string
		Hostname  string
		LogLevel  string
		Service   string
		Category  string
		Fields    string
	}{
		Timestamp: match[1],
		Hostname:  match[2],
		LogLevel:  match[3],
		Service:   match[4],
		Category:  match[5],
		Fields:    match[6],
	}
	ts, err := p.ParseTimestamp(fields.Timestamp)
	if err != nil {
		return nil, err
	}
	event := Security{
		Timestamp: timestamp.RFC3339(ts),
		Hostname:  fields.Hostname,
		LogLevel:  strings.Trim(fields.LogLevel, "[]"),
		Service:   strings.Trim(fields.Service, "[]"),
		Category:  strings.Trim(fields.Category, `"`),
	}

	var handler func(k, v string) error
	switch event.Category {
	case "New Profile":
		handler = event.handleNewProfile
	case "Security Incident":
		handler = event.handleIncident
	case "New Counter Response":
		handler = event.handleNewCounterResponse
	default:
		return nil, errors.Errorf("invalid category %q", event.Category)
	}
	if err := parseFields(fields.Fields, handler); err != nil {
		return nil, err
	}
	event.SetCoreFields(TypeSecurity, &event.Timestamp, &event)
	event.AppendAnyDomainNames(event.Hostname)
	if event.SourceIP != nil {
		event.AppendAnyIPAddress(*event.SourceIP)
	}
	return event.Logs(), nil
}

// nolint:lll
type Security struct {
	Timestamp      timestamp.RFC3339  `json:"timestamp" validate:"required,omitempty" description:"Log entry timestamp"`
	Hostname       string             `json:"hostname,omitempty" description:"The hostname of the appliance"`
	LogLevel       string             `json:"log_level,omitempty" description:"The importance level of a log entry. Can be TRACE, DEBUG, INFO, WARN, or ERROR."`
	Service        string             `json:"service,omitempty" description:"The WebApp Secure service that triggered the security log entry."`
	Category       string             `json:"category,omitempty" description:"Log entry category"`
	ProfileID      *string            `json:"profile_id,omitempty" description:"The numerical ID assigned to the Profile that caused the security alert, or the profile ID that received a Response."`
	ProfileName    *string            `json:"profile_name,omitempty" description:"The friendly name assigned to the Profile that caused the security alert, or the Profile that received a Response."`
	PubKey         *string            `json:"pubkey,omitempty" description:"The Public ID that can be used in conjunction with the Support_Processor to unblock Profiles."`
	Incident       *string            `json:"incident,omitempty" description:"The name of the incident that triggered this security alert."`
	Severity       *uint8             `json:"severity,omitempty" description:"The numerical severity of the incident that triggered this security alert. This can be a number from 0 to 4, inclusive."`
	SourceIP       *string            `json:"source_ip,omitempty" description:"The IP the request that generated this alert originated from."`
	UserAgent      *string            `json:"user_agent,omitempty" description:"The client's user agent string that generated this alert."`
	URL            *string            `json:"url,omitempty" description:"The request URL that generated this alert."`
	Count          *int32             `json:"count,omitempty" description:"The number of times the profile triggered this incident. This is used for certain incidents to decide whether or not to elevate the profile or increase the responses on the profile."`
	FakeResponse   *bool              `json:"fake_response,omitempty" description:"Whether or not (true or false) the response sent back to the client was a fake one created by WebApp Secure."`
	ResponseCode   *string            `json:"response_code,omitempty" description:"The numerical code for the response issued."`
	ResponseName   *string            `json:"response_name,omitempty" description:"The friendly name for the response issued on the profile indicated in the alert."`
	CreatedDate    *timestamp.RFC3339 `json:"created_date,omitempty" description:"The date and time the response was created."`
	DelayDate      *timestamp.RFC3339 `json:"delay_date,omitempty" description:"The date and time the response is set to be delayed until."`
	ExpirationDate *timestamp.RFC3339 `json:"expiration_date,omitempty" description:"The date and time the response is set to expire."`
	ResponseConfig *string            `json:"response_config,omitempty" description:"The configuration used in this response. Displayed as an XML-like node."`
	SilentRunning  *bool              `json:"silent_running,omitempty" description:"Whether or not this Counter Response was set to be silent with the Silent Running service at the time of activation."`

	parsers.PantherLog
}

func normalizeField(k string) (string, error) {
	key := strings.TrimPrefix(k, "MKS_")
	if k != key {
		return key, nil
	}
	return k, errors.Errorf("invalid field %q", k)
}

func (s *Security) handleNewProfile(k, v string) error {
	k, err := normalizeField(k)
	if err != nil {
		return err
	}
	switch k {
	case "ProfileId":
		s.ProfileID = &v
	case "ProfileName":
		s.ProfileName = &v
	case "PubKey":
		s.PubKey = &v
	default:
		return errors.Errorf("invalid field %q", k)
	}
	return nil
}
func (s *Security) handleIncident(k, v string) error {
	k, err := normalizeField(k)
	if err != nil {
		return err
	}
	switch k {
	case "Type":
		s.Incident = &v
	case "Severity":
		n, err := strconv.ParseUint(v, 10, 8)
		if err != nil {
			return err
		}
		sev := uint8(n)
		s.Severity = &sev
	case "ProfileName":
		s.ProfileName = &v
	case "SrcIP":
		s.SourceIP = &v
	case "pubkey":
		s.PubKey = &v
	case "useragent":
		s.UserAgent = &v
	case "url":
		s.URL = &v
	case "count":
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return err
		}
		count := int32(n)
		s.Count = &count
	case "fakeresponse":
		ok, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		s.FakeResponse = &ok
	default:
		return errors.Errorf("invalid field %q", k)
	}
	return nil
}
func (s *Security) handleNewCounterResponse(k, v string) error {
	k, err := normalizeField(k)
	if err != nil {
		return err
	}
	switch k {
	case "ResponseCode":
		s.ResponseCode = &v
	case "ResponseName":
		s.ResponseName = &v
	case "ProfileId":
		s.ProfileID = &v
	case "ProfileName":
		s.ProfileName = &v
	case "ResponseCreated":
		ts, err := time.ParseInLocation(layoutCounterResponseTimestamp, v, time.UTC)
		if err != nil {
			return err
		}
		s.CreatedDate = (*timestamp.RFC3339)(&ts)
	case "ResponseDelayed":
		ts, err := time.ParseInLocation(layoutCounterResponseTimestamp, v, time.UTC)
		if err != nil {
			return err
		}
		s.DelayDate = (*timestamp.RFC3339)(&ts)
	case "ResponseExpires":
		if v != "null" {
			ts, err := time.ParseInLocation(layoutCounterResponseTimestamp, v, time.UTC)
			if err != nil {
				return err
			}
			s.ExpirationDate = (*timestamp.RFC3339)(&ts)
		}
	case "ResponseConfig":
		s.ResponseConfig = &v
	case "SilentRunning":
		ok, err := strconv.ParseBool(v)
		if err != nil {
			return err
		}
		s.SilentRunning = &ok
	default:
		return errors.Errorf("invalid field %q", k)
	}
	return nil
}

const layoutCounterResponseTimestamp = `2006-01-02 15:04:05.999999999`

var rxSecurity = regexp.MustCompile(fmt.Sprintf(`^(%s) (\w+) (%s)\[mws-security-alert\](%s) MKS_Category=(%s) (.*)$`,
	rxTimestamp, // timestamp
	rxBrackets,  // log_level
	rxBrackets,  // service
	rxQuoted,
))

func parseFields(src string, h func(k, v string) error) error {
	var k string
	var v string
	for {
		k, v, src = nextField(src)
		if k == "" {
			return nil
		}
		if err := h(k, v); err != nil {
			return err
		}
	}
}

func nextField(s string) (name, val, tail string) {
	s = skipSpace(s)
	if pos := strings.IndexByte(s, '='); 0 <= pos && pos < len(s) {
		name, tail = s[:pos], s[pos+1:]
		var ok bool
		if val, tail, ok = readValue(tail); ok {
			return
		}
	}
	return "", "", s
}
func readValue(s string) (val, tail string, ok bool) {
	var c byte
	if len(s) > 0 {
		c, tail = s[0], s[1:]
		if c == '"' {
			for i := 0; 0 <= i && i < len(tail); i++ {
				switch c = tail[i]; c {
				case '"':
					return tail[:i], tail[i+1:], true
				case '\\':
					i++
				}
			}
		}
	}
	return "", s, false
}
func skipSpace(s string) string {
	for i := 0; 0 <= i && i < len(s); i++ {
		switch c := s[i]; c {
		case ' ', '\t', '\n', '\r':
		case '\\':
			i++
		default:
			return s[i:]
		}
	}
	return s
}
