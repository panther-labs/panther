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
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/cmd/opstools"
	"github.com/panther-labs/panther/internal/cost"
	"github.com/panther-labs/panther/pkg/awscostexplorer"
)

var (
	START       = flag.String("start", "", "The start time as YYYY-MM-DD UTC (defaults to yesterday)")
	END         = flag.String("end", "", "The end time as YYYY-MM-DD UTC (defaults to now)")
	GRANULARITY = flag.String("granularity", costexplorer.GranularityDaily,
		"Time aggregation granularity one of: "+costexplorer.GranularityHourly+","+
			costexplorer.GranularityDaily+","+costexplorer.GranularityMonthly)
	ACCOUNTS = flag.String("accounts", "", "Comma separated list of AWS linked account ids (defaults to current account)")

	PANTHERREPORTS        = flag.Bool("panther", true, "Include Panther specific reports if true")
	PANTHERREPORTSDETAILS = flag.String("panther.details", strings.Join(defaultPantherDetailedServices, ","),
		"Comma separated list of AWS service names to expand in the panther report")

	SUMMARYREPORTS = flag.Bool("summary", false, "Include summary level if true")

	SERVICEDETAILREPORTS = flag.Bool("servicedetail", false, "Include service level detail if true")

	VERBOSE = flag.Bool("verbose", false, "Enable verbose logging")

	defaultPantherDetailedServices = []string{
		cost.ServiceLambda,
		cost.ServiceS3,
		cost.ServiceCloudWatch,
	}

	startTime, endTime      time.Time
	accounts                []string
	pantherDetailedServices []string
)

func main() {
	opstools.SetUsage("generates cost reports using the costexplorer api")
	flag.Parse()

	log := opstools.MustBuildLogger(*VERBOSE)

	awsSession := session.Must(session.NewSession())

	err := validateFlags(awsSession)
	if err != nil {
		log.Fatal(err)
	}

	reporter := cost.NewReporter(awsSession)

	// focused on Panther related costs
	if *PANTHERREPORTS {
		reports := reporter.NewPantherReports(startTime, endTime, *GRANULARITY, accounts, pantherDetailedServices)
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

func validateFlags(awsSession *session.Session) (err error) {
	if *END == "" {
		endTime = time.Now().UTC()
	} else {
		endTime, err = time.Parse(awscostexplorer.DateFormat, *END)
		if err != nil {
			return errors.Errorf("-end is not correct format: %v", err)
		}
	}

	if *START == "" {
		startTime = endTime.Add(-time.Hour * 24)
	} else {
		startTime, err = time.Parse(awscostexplorer.DateFormat, *START)
		if err != nil {
			return errors.Errorf("-start is not correct format: %v", err)
		}
	}

	if startTime.After(endTime) {
		log.Fatalf("-start is after -end: %v, %v", startTime, endTime)
	}

	if *ACCOUNTS == "" {
		identity, err := sts.New(awsSession).GetCallerIdentity(&sts.GetCallerIdentityInput{})
		if err != nil {
			return errors.Errorf("failed to get caller identity: %v", err)
		}
		accounts = []string{*identity.Account}
	} else {
		accounts = strings.Split(*ACCOUNTS, ",")
	}

	if *PANTHERREPORTSDETAILS != "" {
		pantherDetailedServices = strings.Split(*PANTHERREPORTSDETAILS, ",")
	}

	return nil
}
