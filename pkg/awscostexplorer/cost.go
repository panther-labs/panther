package awscostexplorer

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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/costexplorer"
	"github.com/aws/aws-sdk-go/service/costexplorer/costexploreriface"
	"github.com/pkg/errors"
)

// Cost reporting for Panther using Cost Explorer API:
//     https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsage.html

const (
	DateFormat = "2006-01-02"
)

var (
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

type Reporter struct {
	awsSession *session.Session
	ceClient   costexploreriface.CostExplorerAPI
}

func NewReporter(awsSession *session.Session) *Reporter {
	return &Reporter{
		awsSession: awsSession,
		ceClient:   costexplorer.New(awsSession),
	}
}

type Reports struct {
	Name           string
	Start, End     time.Time
	Granularity    string
	AccountReports map[string][]*Report // accountid -> reports

	reporter *Reporter // back pointer with clients
}

func (r *Reporter) NewSummaryReports(startTime, endTime time.Time, granularity string, accounts []string) *Reports {
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
		reporter: r,

		Name:           "Account Summary",
		Start:          startTime,
		End:            endTime,
		Granularity:    granularity,
		AccountReports: accountReports,
	}
}

func (r *Reporter) NewServiceDetailReports(startTime, endTime time.Time, granularity string, accounts []string) (*Reports, error) {
	startTime = startTime.UTC()
	endTime = endTime.UTC()
	timePeriod := &costexplorer.DateInterval{
		End:   aws.String(endTime.Format(DateFormat)),
		Start: aws.String(startTime.Format(DateFormat)),
	}

	accountReports := make(map[string][]*Report)

	services, err := r.GetServices(timePeriod)
	if err != nil {
		return nil, err
	}

	for i, account := range accounts {
		var reports []*Report

		for _, service := range services {
			reports = append(reports, &Report{
				Name:        fmt.Sprintf("%s Cost and Usage By Usage Type", service),
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     Metrics,
				Filter: &costexplorer.Expression{
					Dimensions: &costexplorer.DimensionValues{
						Key:    aws.String(costexplorer.DimensionService),
						Values: []*string{aws.String(service)},
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
		reporter: r,

		Name:           "Account Service Details",
		Start:          startTime,
		End:            endTime,
		Granularity:    granularity,
		AccountReports: accountReports,
	}, nil
}

func (r *Reporter) Run(report *Report) error {
	return report.run(r.ceClient)
}

func (pr *Reports) Run() error {
	for _, reports := range pr.AccountReports {
		for _, report := range reports {
			err := pr.reporter.Run(report)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (pr Reports) Print() {
	for account, reports := range pr.AccountReports {
		fmt.Printf("%s for Account: %s\n", pr.Name, account)
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

func (report *Report) run(ceClient costexploreriface.CostExplorerAPI) error {
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
			return errors.Wrapf(err, "Run() failed for %s", report.Name)
		}
		if report.Output.NextPageToken == nil {
			break
		}
		input.NextPageToken = report.Output.NextPageToken
	}
	return nil
}

// GetServices returns the available names for services (useful to find new services)
func (r *Reporter) GetServices(timePeriod *costexplorer.DateInterval) (services []string, err error) {
	for {
		input := &costexplorer.GetDimensionValuesInput{
			Dimension:  aws.String(costexplorer.DimensionService),
			TimePeriod: timePeriod,
		}
		output, err := r.ceClient.GetDimensionValues(input)
		if err != nil {
			return nil, errors.Wrap(err, "GetServices() failed")
		}
		for _, dm := range output.DimensionValues {
			services = append(services, *dm.Value)
		}
		if output.NextPageToken == nil {
			break
		}
		input.NextPageToken = output.NextPageToken
	}
	return services, nil
}
