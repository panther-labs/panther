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
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/costexplorer"
	"github.com/aws/aws-sdk-go/service/costexplorer/costexploreriface"
)

// Cost reporting for Panther using Cost Explorer API:
//     https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsage.html

const (
	DateFormat = "2006-01-02"

	// use GetServices() to discover specific names required
	ServiceAthena        = "Amazon Athena"
	ServiceCloudWatch    = "AmazonCloudWatch"
	ServiceDDB           = "Amazon DynamoDB"
	ServiceGlue          = "AWS Glue"
	ServiceKMS           = "AWS Key Management Service"
	ServiceLambda        = "AWS Lambda"
	ServiceS3            = "Amazon Simple Storage Service"
	ServiceSQS           = "Amazon Simple Queue Service"
	ServiceSNS           = "Amazon Simple Notification Service"
	ServiceStepFunctions = "AWS Step Functions"
)

var (
	Services = []string{
		ServiceLambda,
		ServiceDDB,
		ServiceS3,
		ServiceSQS,
		ServiceSNS,
		ServiceCloudWatch,
		ServiceAthena,
		ServiceGlue,
		ServiceKMS,
		ServiceStepFunctions,
	}

	Metrics = []*string{
		aws.String(costexplorer.MetricUsageQuantity),
		aws.String(costexplorer.MetricNormalizedUsageAmount),

		aws.String(costexplorer.MetricBlendedCost),
		aws.String(costexplorer.MetricUnblendedCost),
		aws.String(costexplorer.MetricAmortizedCost),
		aws.String(costexplorer.MetricNetAmortizedCost),
		aws.String(costexplorer.MetricNetUnblendedCost),
	}
)

type Reports struct {
	Start, End     time.Time
	Granularity    string
	AccountReports map[string][]*Report // accountid -> reports
}

func NewSummaryReports(startTime, endTime time.Time, granularity string, accounts []string) *Reports {
	startTime = startTime.UTC()
	endTime = endTime.UTC()
	timePeriod := &costexplorer.DateInterval{
		End:   aws.String(endTime.Format(DateFormat)),
		Start: aws.String(startTime.Format(DateFormat)),
	}

	accountReports := make(map[string][]*Report)

	for i, account := range accounts {
		reports := []*Report{
			{
				Name:        "Total Cost and Usage",
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     Metrics,
			},
			{
				Name:        "Cost and Usage By Service",
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     Metrics,
				GroupBy: []*costexplorer.GroupDefinition{
					{
						Key:  aws.String(costexplorer.DimensionService),
						Type: aws.String(costexplorer.GroupDefinitionTypeDimension),
					},
				},
			},
		}

		accountReports[account] = reports
	}

	return &Reports{
		Start:          startTime,
		End:            endTime,
		Granularity:    granularity,
		AccountReports: accountReports,
	}
}

func NewServiceDetailReports(startTime, endTime time.Time, granularity string, accounts []string) *Reports {
	startTime = startTime.UTC()
	endTime = endTime.UTC()
	timePeriod := &costexplorer.DateInterval{
		End:   aws.String(endTime.Format(DateFormat)),
		Start: aws.String(startTime.Format(DateFormat)),
	}

	accountReports := make(map[string][]*Report)

	for i, account := range accounts {
		var reports []*Report
		for _, service := range Services {
			reports = append(reports, &Report{
				Name:        fmt.Sprintf("%s Cost and Usage By Usage Type", service),
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     Metrics,
				Filter: &costexplorer.Expression{
					Dimensions: &costexplorer.DimensionValues{
						Key:          aws.String(costexplorer.DimensionService),
						MatchOptions: nil,
						Values:       []*string{aws.String(service)},
					},
				},
				GroupBy: []*costexplorer.GroupDefinition{
					{
						Key:  aws.String(costexplorer.DimensionUsageType),
						Type: aws.String(costexplorer.GroupDefinitionTypeDimension),
					},
				},
			})
		}

		accountReports[account] = reports
	}

	return &Reports{
		Start:          startTime,
		End:            endTime,
		Granularity:    granularity,
		AccountReports: accountReports,
	}
}

func (pr *Reports) Run(ceClient costexploreriface.CostExplorerAPI) {
	for _, reports := range pr.AccountReports {
		for _, report := range reports {
			report.Run(ceClient)
		}
	}
}

func (pr Reports) Print() {
	for account, reports := range pr.AccountReports {
		fmt.Printf("Account: %s\n\n", account)
		for _, report := range reports {
			report.Print()
		}
	}
}

type Report struct {
	Name        string
	Accounts    []*string
	TimePeriod  *costexplorer.DateInterval
	Granularity *string
	Metrics     []*string
	Filter      *costexplorer.Expression
	GroupBy     []*costexplorer.GroupDefinition

	Output *costexplorer.GetCostAndUsageOutput
}

func (report *Report) Print() {
	fmt.Printf("%s\n%v\n\n", report.Name, *report.Output)
}

func (report *Report) Run(ceClient costexploreriface.CostExplorerAPI) {
	filter := report.Filter
	if len(report.Accounts) > 0 { // qualify by account?
		accountFilter := &costexplorer.Expression{
			Dimensions: &costexplorer.DimensionValues{
				Key:          aws.String(costexplorer.DimensionLinkedAccount),
				MatchOptions: nil,
				Values:       report.Accounts,
			},
		}
		if filter == nil {
			filter = accountFilter
		} else {
			filter = &costexplorer.Expression{
				And: []*costexplorer.Expression{
					filter,
					accountFilter,
				},
			}
		}
	}
	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod:  report.TimePeriod,
		Filter:      filter,
		Granularity: report.Granularity,
		GroupBy:     report.GroupBy,
		Metrics:     report.Metrics,
	}
	var err error
	for {
		report.Output, err = ceClient.GetCostAndUsage(input)
		if err != nil {
			log.Fatal(err)
		}
		if report.Output.NextPageToken == nil {
			break
		}
		input.NextPageToken = report.Output.NextPageToken
	}
}

// GetServices prints the available names for services (useful to find new services)
func GetServices(ceClient costexploreriface.CostExplorerAPI, timePeriod *costexplorer.DateInterval) {
	input := &costexplorer.GetDimensionValuesInput{
		Context:       nil,
		Dimension:     aws.String(costexplorer.DimensionService),
		NextPageToken: nil,
		SearchString:  nil,
		TimePeriod:    timePeriod,
	}
	output, err := ceClient.GetDimensionValues(input)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%#v\n", *output)
}
