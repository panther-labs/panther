package utils

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
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"go.uber.org/zap"
)

// GetRegions returns all the active AWS regions for a given account.
func GetRegions(ec2Svc ec2iface.EC2API) (regions []*string) {
	regionsOutput, err := ec2Svc.DescribeRegions(&ec2.DescribeRegionsInput{})

	if err != nil {
		LogAWSError("EC2.DescribeRegions", err)
		return nil
	}

	for _, region := range regionsOutput.Regions {
		regions = append(regions, region.RegionName)
	}
	return
}

// GetServiceRegions returns the intersection of the active regions passed in by the poller input
// and the regions specific to the given service
func GetServiceRegions(activeRegions []*string, serviceID string) (regions []*string) {
	serviceRegions, exists := endpoints.RegionsForService(
		endpoints.DefaultPartitions(),
		endpoints.AwsPartitionID,
		serviceID,
	)
	if !exists {
		zap.L().Error("no regions found for service", zap.String("service", serviceID))
		return nil
	}

	for _, region := range activeRegions {
		if _, ok := serviceRegions[*region]; ok {
			regions = append(regions, region)
		}
	}
	if len(regions) == 0 {
		activeRegionsS := make([]string, len(activeRegions))
		for _, region := range regions {
			activeRegionsS = append(activeRegionsS, *region)
		}
		zap.L().Debug(
			"no shared regions found between service regions and active regions",
			zap.String("service", serviceID),
			zap.Strings("activeRegions", activeRegionsS),
		)
	}
	return
}
