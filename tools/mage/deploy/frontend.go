package deploy

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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/joho/godotenv"

	"github.com/panther-labs/panther/tools/cfnstacks"
	"github.com/panther-labs/panther/tools/mage/pkg"
	"github.com/panther-labs/panther/tools/mage/util"
)

const awsEnvFile = "out/.env.aws"

func deployFrontend(settings *PantherConfig, packager *pkg.Packager, bootstrapOutputs map[string]string) error {
	// Save .env file (only used when running web server locally)
	if err := godotenv.Write(
		map[string]string{
			"AWS_ACCOUNT_ID":                       util.AccountID(packager.AwsConfig),
			"AWS_REGION":                           packager.AwsConfig.Region,
			"WEB_APPLICATION_GRAPHQL_API_ENDPOINT": bootstrapOutputs["GraphQLApiEndpoint"],
			"WEB_APPLICATION_USER_POOL_ID":         bootstrapOutputs["UserPoolId"],
			"WEB_APPLICATION_USER_POOL_CLIENT_ID":  bootstrapOutputs["AppClientId"],
		},
		awsEnvFile,
	); err != nil {
		return fmt.Errorf("failed to write ENV variables to file %s: %v", awsEnvFile, err)
	}

	var err error
	packager.DockerImageID, err = pkg.DockerBuild(packager.Log, filepath.Join("deployments", "Dockerfile"))
	if err != nil {
		return err
	}

	params := map[string]string{
		"AlarmTopicArn":              bootstrapOutputs["AlarmTopicArn"],
		"AppClientId":                bootstrapOutputs["AppClientId"],
		"CertificateArn":             settings.Web.CertificateArn,
		"CloudWatchLogRetentionDays": strconv.Itoa(settings.Monitoring.CloudWatchLogRetentionDays),
		"CustomResourceVersion":      customResourceVersion(),
		"ElbArn":                     bootstrapOutputs["LoadBalancerArn"],
		"ElbFullName":                bootstrapOutputs["LoadBalancerFullName"],
		"ElbTargetGroup":             bootstrapOutputs["LoadBalancerTargetGroup"],
		"FirstUserEmail":             settings.Setup.FirstUser.Email,
		"FirstUserFamilyName":        settings.Setup.FirstUser.FamilyName,
		"FirstUserGivenName":         settings.Setup.FirstUser.GivenName,
		"GraphQLApiEndpoint":         bootstrapOutputs["GraphQLApiEndpoint"],
		"InitialAnalysisPackUrls":    strings.Join(settings.Setup.InitialAnalysisSets, ","),
		"PantherCommit":              util.CommitSha(),
		"PantherVersion":             util.Semver(),
		"SecurityGroup":              bootstrapOutputs["WebSecurityGroup"],
		"SubnetOneId":                bootstrapOutputs["SubnetOneId"],
		"SubnetTwoId":                bootstrapOutputs["SubnetTwoId"],
		"UserPoolId":                 bootstrapOutputs["UserPoolId"],
	}
	_, err = Stack(packager, cfnstacks.FrontendTemplate, cfnstacks.Frontend, params)
	return err
}
