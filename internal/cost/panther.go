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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/costexplorer"
)

// Specifically tailored reports for Panther

const (
	PantherCostKey    = "BlendedCost" // no constant for this
	PantherCostMetric = costexplorer.MetricBlendedCost
	PantherUsageKey   = "UsageQuantity" // no constant for this
)

type PantherReports struct {
	Reports
}

func NewPantherSummaryReports(startTime, endTime time.Time, granularity string, accounts []string) *PantherReports {
	startTime = startTime.UTC()
	endTime = endTime.UTC()
	timePeriod := &costexplorer.DateInterval{
		End:   aws.String(endTime.Format(DateFormat)),
		Start: aws.String(startTime.Format(DateFormat)),
	}

	accountReports := make(map[string][]*Report)

	// narrow the returned values
	pantherMetrics := []*string{
		aws.String(costexplorer.MetricUsageQuantity),
		aws.String(PantherCostMetric),
	}

	for i, account := range accounts {
		reports := []*Report{
			{
				Name:        "Total Cost and Usage",
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     pantherMetrics,
			},
			{
				Name:        "Cost and Usage By Service",
				Accounts:    []*string{&accounts[i]},
				TimePeriod:  timePeriod,
				Granularity: &granularity,
				Metrics:     pantherMetrics,
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

	return &PantherReports{
		Reports: Reports{
			Start:          startTime,
			End:            endTime,
			Granularity:    granularity,
			AccountReports: accountReports,
		},
	}
}

func (pr PantherReports) Print() {
	for account, reports := range pr.AccountReports {
		// we assume a specific structure for PantherReports
		totalReport := reports[0]
		serviceReport := reports[1]
		fmt.Printf("Account: %s\n", account)
		fmt.Printf("\tTime Interval: %s - %s (%s)\n",
			pr.Start.Format(DateFormat), pr.End.Format(DateFormat), pr.Granularity)
		fmt.Printf("\tTotal Cost: %f\n", pantherCost(totalReport))
		s3Cost := pantherS3Cost(serviceReport)
		fmt.Printf("\tS3 Cost: %f\n", s3Cost)
		lambdaCost := pantherLambdaCost(serviceReport)
		fmt.Printf("\tLambda Cost: %f\n", lambdaCost)
		cwCost := pantherCloudWatchCost(serviceReport)
		fmt.Printf("\tCloudWatch Cost: %f\n", cwCost)
		sqsCost := pantherSQSCost(serviceReport)
		fmt.Printf("\tSQS Cost: %f\n", sqsCost)
		snsCost := pantherSNSCost(serviceReport)
		fmt.Printf("\tSNS Cost: %f\n", snsCost)
	}
}

func pantherCost(r *Report) (cost float64) {
	for _, byTime := range r.Output.ResultsByTime {
		cost += readFloat(*byTime.Total[PantherCostKey].Amount)
	}
	return cost
}

func pantherS3Cost(r *Report) (cost float64) {
	for _, byTime := range r.Output.ResultsByTime {
		for _, group := range byTime.Groups {
			if *group.Keys[0] == ServiceS3 {
				cost += readFloat(*group.Metrics[PantherCostKey].Amount)
				break
			}
		}
	}
	return cost
}

func pantherLambdaCost(r *Report) (cost float64) {
	for _, byTime := range r.Output.ResultsByTime {
		for _, group := range byTime.Groups {
			if *group.Keys[0] == ServiceLambda {
				cost += readFloat(*group.Metrics[PantherCostKey].Amount)
				break
			}
		}
	}
	return cost
}

func pantherCloudWatchCost(r *Report) (cost float64) {
	for _, byTime := range r.Output.ResultsByTime {
		for _, group := range byTime.Groups {
			if *group.Keys[0] == ServiceCloudWatch {
				cost += readFloat(*group.Metrics[PantherCostKey].Amount)
				break
			}
		}
	}
	return cost
}

func pantherSQSCost(r *Report) (cost float64) {
	for _, byTime := range r.Output.ResultsByTime {
		for _, group := range byTime.Groups {
			if *group.Keys[0] == ServiceSQS {
				cost += readFloat(*group.Metrics[PantherCostKey].Amount)
				break
			}
		}
	}
	return cost
}

func pantherSNSCost(r *Report) (cost float64) {
	for _, byTime := range r.Output.ResultsByTime {
		for _, group := range byTime.Groups {
			if *group.Keys[0] == ServiceSNS {
				cost += readFloat(*group.Metrics[PantherCostKey].Amount)
				break
			}
		}
	}
	return cost
}

func readFloat(s string) float64 {
	f, err := strconv.ParseFloat(s, 32)
	if err != nil {
		panic(err)
	}
	return f
}
