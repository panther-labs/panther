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
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestSecurityParserIncident(t *testing.T) {
	//nolint:lll
	log := `Oct 13 16:33:13 jwas1 [INFO][mws-security-alert][traffic-info] MKS_Category="Security Incident" MKS_Type="Apache Configuration Requested" MKS_Severity="2" MKS_ProfileName="Brett 8356" MKS_SrcIP="10.10.0.117" MKS_pubkey="el4urlypSXuRHOM3IoLT" MKS_useragent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.101 Safari/537.36" MKS_url="http://jwas1.jsec.net:80/.htaccess" MKS_count="1" MKS_fakeresponse="true"`
	now := time.Now()
	tm := expectedTestDate(time.Date(now.Year(), time.October, 13, 16, 33, 13, 0, time.UTC))
	event := Security{
		Timestamp:   timestamp.RFC3339(tm),
		Service:     "traffic-info",
		Hostname:    "jwas1",
		LogLevel:    "INFO",
		Category:    "Security Incident",
		Incident:    aws.String("Apache Configuration Requested"),
		Severity:    aws.Uint8(2),
		ProfileName: aws.String("Brett 8356"),
		SourceIP:    aws.String("10.10.0.117"),
		PubKey:      aws.String("el4urlypSXuRHOM3IoLT"),
		//nolint:lll
		UserAgent:    aws.String("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.101 Safari/537.36"),
		URL:          aws.String("http://jwas1.jsec.net:80/.htaccess"),
		Count:        aws.Int32(1),
		FakeResponse: aws.Bool(true),
	}
	event.SetCoreFields(TypeSecurity, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyIPAddress("10.10.0.117")
	event.AppendAnyDomainNames("jwas1")
	testutil.CheckPantherParser(t, log, NewSecurityParser(), &event.PantherLog)
}
func TestSecurityNewProfile(t *testing.T) {
	//nolint:lll
	log := `Oct 13 16:33:13 jwas1 [INFO][mws-security-alert][traffic-info] MKS_Category="New Profile" MKS_ProfileId="3811" MKS_ProfileName="Brett 8356" MKS_PubKey="el4urlypSXuRHOM3IoLT"`
	now := time.Now()
	tm := expectedTestDate(time.Date(now.Year(), time.October, 13, 16, 33, 13, 0, time.UTC))
	event := Security{
		Timestamp:   timestamp.RFC3339(tm),
		Service:     "traffic-info",
		Hostname:    "jwas1",
		LogLevel:    "INFO",
		Category:    "New Profile",
		ProfileID:   aws.String("3811"),
		ProfileName: aws.String("Brett 8356"),
		PubKey:      aws.String("el4urlypSXuRHOM3IoLT"),
	}
	event.SetCoreFields(TypeSecurity, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyDomainNames("jwas1")
	testutil.CheckPantherParser(t, log, NewSecurityParser(), &event.PantherLog)
}
func TestSecurityNewCounterResponse(t *testing.T) {
	//nolint:lll
	log := `Oct 13 16:33:55 jwas1 [INFO][mws-security-alert][auto-response] MKS_Category="New Counter Response" MKS_ResponseCode="BL" MKS_ResponseName="Block User" MKS_ProfileId="3811" MKS_ProfileName="Brett 8356" MKS_ResponseCreated="2014-10-13 16:33:54.0" MKS_ResponseDelayed="2014-10-13 16:33:54.0" MKS_ResponseExpires="null" MKS_ResponseConfig="<config />" MKS_SilentRunning="true"`
	now := time.Now()
	tm := expectedTestDate(time.Date(now.Year(), time.October, 13, 16, 33, 55, 0, time.UTC))
	created := time.Date(2014, 10, 13, 16, 33, 54, 0, time.UTC)
	delayed := time.Date(2014, 10, 13, 16, 33, 54, 0, time.UTC)
	event := Security{
		Timestamp:      timestamp.RFC3339(tm),
		Service:        "auto-response",
		Hostname:       "jwas1",
		LogLevel:       "INFO",
		Category:       "New Counter Response",
		ProfileID:      aws.String("3811"),
		ProfileName:    aws.String("Brett 8356"),
		CreatedDate:    (*timestamp.RFC3339)(&created),
		DelayDate:      (*timestamp.RFC3339)(&delayed),
		ResponseConfig: aws.String("<config />"),
		ResponseName:   aws.String("Block User"),
		ResponseCode:   aws.String("BL"),
		SilentRunning:  aws.Bool(true),
	}
	event.SetCoreFields(TypeSecurity, (*timestamp.RFC3339)(&tm), &event)
	event.AppendAnyDomainNames("jwas1")
	testutil.CheckPantherParser(t, log, NewSecurityParser(), &event.PantherLog)
}
