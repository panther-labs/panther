package cost

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
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/cloudwatch/cloudwatchiface"
	"github.com/aws/aws-sdk-go/service/costexplorer"

	"github.com/panther-labs/panther/pkg/awscostexplorer"
)

// Specifically tailored reports for Panther

const (
	PantherCostKey    = "BlendedCost" // no constant for this
	PantherCostMetric = costexplorer.MetricBlendedCost
	PantherUsageKey   = "UsageQuantity" // no constant for this

	// use GetServices() to discover specific names required
	ServiceAppSync              = "AWS AppSync"
	ServiceAthena               = "Amazon Athena"
	ServiceCognito              = "Amazon Cognito"
	ServiceCloudWatch           = "AmazonCloudWatch"
	ServiceEC2ContainerRegistry = "Amazon EC2 Container Registry (ECR)"
	ServiceEFS                  = "Amazon Elastic File System"
	ServiceELB                  = "Amazon Elastic Load Balancing"
	ServiceDDB                  = "Amazon DynamoDB"
	ServiceFirehose             = "Amazon Kinesis Firehose"
	ServiceGlue                 = "AWS Glue"
	ServiceKMS                  = "AWS Key Management Service"
	ServiceLambda               = "AWS Lambda"

	ServiceS3             = "Amazon Simple Storage Service"
	ServiceSecretsManager = "AWS Secrets Manager" // nolint:gosec
	ServiceSQS            = "Amazon Simple Queue Service"
	ServiceSNS            = "Amazon Simple Notification Service"
	ServiceStepFunctions  = "AWS Step Functions"
)

var (
	pantherServices = []string{
		ServiceAppSync,
		ServiceAthena,
		ServiceCognito,
		ServiceCloudWatch,
		ServiceDDB,
		ServiceEC2ContainerRegistry,
		ServiceEFS,
		ServiceELB,
		ServiceFirehose,
		ServiceGlue,
		ServiceKMS,
		ServiceLambda,
		ServiceS3,
		ServiceSecretsManager,
		ServiceSQS,
		ServiceSNS,
		ServiceStepFunctions,
	}

	// filter all queries by Panther tags to focus
	pantherFilter = &costexplorer.Expression{
		Tags: &costexplorer.TagValues{
			Key:    aws.String("Application"),
			Values: []*string{aws.String("Panther")},
		},
	}
)

type Reporter struct {
	awscostexplorer.Reporter
	cloudwatchClient cloudwatchiface.CloudWatchAPI
}

func NewReporter(awsSession *session.Session) *Reporter {
	return &Reporter{
		Reporter:         *awscostexplorer.NewReporter(awsSession),
		cloudwatchClient: cloudwatch.New(awsSession),
	}
}

type PantherReports struct {
	Start, End       time.Time
	Granularity      string
	AccountReports   map[string]*PantherReport // accountid -> reports
	DetailedServices []string                  // services to expand

	reporter *awscostexplorer.Reporter // back pointer with clients
}

type PantherReport struct {
	totalUsage           *awscostexplorer.Report
	byServiceUsage       *awscostexplorer.Report
	detailedServiceUsage map[string]*awscostexplorer.Report // service -> report
}

func (r *Reporter) NewPantherReports(startTime, endTime time.Time, granularity string,
	accounts, detailedServices []string) *PantherReports {

	startTime = startTime.UTC()
	endTime = endTime.UTC()
	timePeriod := &costexplorer.DateInterval{
		End:   aws.String(endTime.Format(awscostexplorer.DateFormat)),
		Start: aws.String(startTime.Format(awscostexplorer.DateFormat)),
	}

	accountReports := make(map[string]*PantherReport)

	// narrow the returned values
	pantherMetrics := []*string{
		aws.String(costexplorer.MetricUsageQuantity),
		aws.String(PantherCostMetric),
	}

	for i, account := range accounts {
		detailedServiceUsage := make(map[string]*awscostexplorer.Report)
		// for these run detailed reports
		for _, service := range detailedServices {
			detailedServiceUsage[service] = &awscostexplorer.Report{
				Name:        fmt.Sprintf("%s Cost and Usage By Usage Type", service),
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     pantherMetrics,
				Filter: &costexplorer.Expression{
					And: []*costexplorer.Expression{
						pantherFilter,
						{
							Dimensions: &costexplorer.DimensionValues{
								Key:    aws.String(costexplorer.DimensionService),
								Values: []*string{aws.String(service)},
							},
						},
					},
				},
				GroupBy: []*costexplorer.GroupDefinition{
					{
						Key:  aws.String(costexplorer.DimensionUsageType),
						Type: aws.String(costexplorer.GroupDefinitionTypeDimension),
					},
				},
			}
		}

		pantherReport := &PantherReport{
			totalUsage: &awscostexplorer.Report{
				Name:        "Total Cost and Usage",
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     pantherMetrics,
				Filter:      pantherFilter,
			},
			byServiceUsage: &awscostexplorer.Report{
				Name:        "Cost and Usage By Service",
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     pantherMetrics,
				Filter:      pantherFilter,
				GroupBy: []*costexplorer.GroupDefinition{
					{
						Key:  aws.String(costexplorer.DimensionService),
						Type: aws.String(costexplorer.GroupDefinitionTypeDimension),
					},
				},
			},
			detailedServiceUsage: detailedServiceUsage,
		}

		accountReports[account] = pantherReport
	}

	return &PantherReports{
		reporter: &r.Reporter,

		Start:            startTime,
		End:              endTime,
		Granularity:      granularity,
		AccountReports:   accountReports,
		DetailedServices: detailedServices,
	}
}

func (pr PantherReports) Run() error {
	for _, reports := range pr.AccountReports {
		err := pr.reporter.Run(reports.totalUsage)
		if err != nil {
			return err
		}
		err = pr.reporter.Run(reports.byServiceUsage)
		if err != nil {
			return err
		}
		for _, detailedUsageReport := range reports.detailedServiceUsage {
			err = pr.reporter.Run(detailedUsageReport)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (pr PantherReports) Print() {
	for account, report := range pr.AccountReports {
		// we assume a specific structure for PantherReports
		fmt.Printf("Panther Summary for Account: %s\n", account)

		// calc space between key and value
		longestServiceName := 0
		for _, pantherService := range pantherServices {
			if len(pantherService) > longestServiceName {
				longestServiceName = len(pantherService)
			}
		}
		valueSpace := strings.Repeat(" ", longestServiceName) + "\t"

		printPantherKeyValue("Time Interval", valueSpace,
			fmt.Sprintf("%s - %s (%s)",
				pr.Start.Format(awscostexplorer.DateFormat), pr.End.Format(awscostexplorer.DateFormat), pr.Granularity))

		totalCost, totalCostUnit := pantherTotalCost(report.totalUsage)
		totalCostValue := fmt.Sprintf("%f %s", totalCost, totalCostUnit)
		printPantherKeyValue("Total Cost", valueSpace, totalCostValue)

		for _, pantherService := range pantherServices {
			if printPantherServiceCost(report.byServiceUsage, pantherService, valueSpace) > 0.0 {
				// check for detailed reports
				for serviceName, detailedUsageReport := range report.detailedServiceUsage {
					if serviceName == pantherService {
						printPantherDetailServiceCosts(detailedUsageReport, valueSpace)
					}
				}
			}
		}

		fmt.Println() // trailing separator
	}
}

func pantherTotalCost(r *awscostexplorer.Report) (cost float64, unit string) {
	for _, byTime := range r.Output.ResultsByTime {
		cost += readFloat(*byTime.Total[PantherCostKey].Amount)
		unit = *byTime.Total[PantherCostKey].Unit // overwrite, they should be the same
	}
	return cost, unit
}

func printPantherServiceCost(r *awscostexplorer.Report, service, valueSpace string) float64 {
	cost, unit := pantherServiceCost(r, service)
	if cost > 0.0 {
		value := fmt.Sprintf("%f %s", cost, unit)
		printPantherKeyValue(service, valueSpace, value)
	}
	return cost
}

func printPantherDetailServiceCosts(r *awscostexplorer.Report, valueSpace string) {
	addDates := len(r.Output.ResultsByTime) > 1 // only expand per date range if there is more than one
	for _, byTime := range r.Output.ResultsByTime {
		if addDates {
			value := fmt.Sprintf("%s - %s", *byTime.TimePeriod.Start, *byTime.TimePeriod.End)
			printPantherKeyValue("\tTime Interval:", valueSpace, value)
		}
		for _, group := range byTime.Groups {
			cost := *group.Metrics[PantherCostKey].Amount
			if readFloat(cost) <= 0.0 {
				continue
			}
			costUnit := *group.Metrics[PantherCostKey].Unit
			usage := *group.Metrics[PantherUsageKey].Amount
			usageUnit := *group.Metrics[PantherUsageKey].Unit
			value := fmt.Sprintf("%s %s @ %s %s", usage, usageUnit, cost, costUnit)
			// indent under summary and add details
			printPantherKeyValue("\t\t"+*group.Keys[0], valueSpace, value)
		}
	}
}

func printPantherKeyValue(key, valueSpace string, value interface{}) {
	fmt.Printf("\t%s:%s%v\n",
		key,
		valueSpace[0:len(valueSpace)-len(key)],
		value)
}

func pantherServiceCost(r *awscostexplorer.Report, service string) (cost float64, unit string) {
	for _, byTime := range r.Output.ResultsByTime {
		for _, group := range byTime.Groups {
			if *group.Keys[0] == service {
				cost += readFloat(*group.Metrics[PantherCostKey].Amount)
				unit = *group.Metrics[PantherCostKey].Unit // overwrite, they should be the same
				break
			}
		}
	}
	return cost, unit
}

func readFloat(s string) float64 {
	f, err := strconv.ParseFloat(s, 32)
	if err != nil {
		panic(err)
	}
	return f
}
