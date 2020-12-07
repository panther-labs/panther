package main

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
	"flag"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/costexplorer"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/panther-labs/panther/internal/cost"
)

var (
	START       = flag.String("start", "", "The start time as YYYY-MM-DD UTC (defaults to yesterday)")
	END         = flag.String("end", "", "The end time as YYYY-MM-DD UTC (defaults to now)")
	GRANULARITY = flag.String("granularity", costexplorer.GranularityDaily,
		"Time aggregation granularity one of: "+costexplorer.GranularityHourly+","+
			costexplorer.GranularityDaily+","+costexplorer.GranularityMonthly)
	ACCOUNTS = flag.String("accounts", "", "Comma separated list of AWS linked account ids")

	PANTHERREPORTS       = flag.Bool("panther", true, "Include Panther specific reports if true")
	SUMMARYREPORTS       = flag.Bool("summary", false, "Include summary level if true")
	SERVICEDETAILREPORTS = flag.Bool("servicedetail", false, "Include service level detail if true")

	startTime, endTime time.Time
	accounts           []string
)

func main() {
	flag.Parse()

	awsSession := session.Must(session.NewSession())

	validateFlags(awsSession)

	reporter := cost.NewReporter(awsSession)

	// focused on Panther related costs
	if *PANTHERREPORTS {
		reports := reporter.NewPantherReports(startTime, endTime, *GRANULARITY, accounts)
		err := reports.Run()
		if err != nil {
			log.Fatal(err)
		}
		reports.Print()
	}

	// Overall summary costs and usage
	if *SUMMARYREPORTS {
		reports := reporter.NewSummaryReports(startTime, endTime, *GRANULARITY, accounts)
		err := reports.Run()
		if err != nil {
			log.Fatal(err)
		}
		reports.Print()
	}

	// Detailed costs and usage per service
	if *SERVICEDETAILREPORTS {
		reports, err := reporter.NewServiceDetailReports(startTime, endTime, *GRANULARITY, accounts)
		if err != nil {
			log.Fatal(err)
		}
		err = reports.Run()
		if err != nil {
			log.Fatal(err)
		}
		reports.Print()
	}
}

func validateFlags(awsSession *session.Session) {
	var err error

	if *END == "" {
		endTime = time.Now().UTC()
	} else {
		endTime, err = time.Parse(cost.DateFormat, *END)
		if err != nil {
			log.Fatalf("-end is not correct format: %v", err)
		}
	}

	if *START == "" {
		startTime = endTime.Add(-time.Hour * 24)
	} else {
		startTime, err = time.Parse(cost.DateFormat, *START)
		if err != nil {
			log.Fatalf("-start is not correct format: %v", err)
		}
	}

	if startTime.After(endTime) {
		log.Fatalf("-start is after -end: %v, %v", startTime, endTime)
	}

	if *ACCOUNTS == "" {
		identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			log.Fatalf("failed to get caller identity: %v", err)
		}
		accounts = []string{*identity.Account}
	} else {
		accounts = strings.Split(*ACCOUNTS, ",")
	}
}
