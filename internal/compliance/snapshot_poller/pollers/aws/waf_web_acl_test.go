package aws

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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/aws/awstest"
)

func TestWafRegionalListWebAcls(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvc([]string{"ListWebACLs"})

	out, marker, err := listWebAcls(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestWafRegionalListWebAclsError(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvcError([]string{"ListWebACLs"})

	out, marker, err := listWebAcls(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestWafRegionalListTagsForResource(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvc([]string{"ListTagsForResource"})

	out, err := listTagsForResourceWaf(mockSvc, awstest.ExampleWebAclID)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestWafRegionalListTagsForResourceError(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvcError([]string{"ListTagsForResource"})

	out, err := listTagsForResourceWaf(mockSvc, awstest.ExampleWebAclID)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestWafRegionalGetWebAcl(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvc([]string{"GetWebACL"})

	out, err := getWebACL(mockSvc, aws.String("asdfasdf-x123-y123-z123-1234asdf1234"))

	assert.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestWafRegionalGetRule(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvc([]string{"GetRule"})

	out, err := getRule(mockSvc, awstest.ExampleWebAclID)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestWafRegionalGetRuleError(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvcError([]string{"GetRule"})

	out, err := getRule(mockSvc, awstest.ExampleWebAclID)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestWafRegionalGetWebAclError(t *testing.T) {
	mockSvc := awstest.BuildMockWafRegionalSvcError([]string{"GetWebACL"})

	out, err := getWebACL(mockSvc, aws.String("asdfasdf-x123-y123-z123-1234asdf1234"))

	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestBuildWafRegionalWebAclSnapshot(t *testing.T) {
	mockWafRegionalSvc := awstest.BuildMockWafRegionalSvcAll()

	wafRegionalWebAclSnapshot, err := buildWafWebACLSnapshot(
		mockWafRegionalSvc,
		aws.String("asdfasdf-x123-y123-z123-1234asdf1234"),
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, wafRegionalWebAclSnapshot.ID)
	assert.NotEmpty(t, wafRegionalWebAclSnapshot.Rules)
	assert.NotEmpty(t, wafRegionalWebAclSnapshot.DefaultAction)
}

func TestBuildWafRegionalWebAclSnapshotError(t *testing.T) {
	mockWafRegionalSvc := awstest.BuildMockWafRegionalSvcAllError()

	wafRegionalWebAclSnapshot, err := buildWafWebACLSnapshot(
		mockWafRegionalSvc,
		aws.String("asdfasdf-x123-y123-z123-1234asdf1234"),
	)

	assert.Nil(t, wafRegionalWebAclSnapshot)
	assert.Error(t, err)
}

func TestWafListWebAcls(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvc([]string{"ListWebACLs"})

	out, marker, err := listWebAcls(mockSvc, nil)
	assert.NotEmpty(t, out)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestWafListWebAclsError(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvcError([]string{"ListWebACLs"})

	out, marker, err := listWebAcls(mockSvc, nil)
	assert.Nil(t, out)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestWafListTagsForResource(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvc([]string{"ListTagsForResource"})

	out, err := listTagsForResourceWaf(mockSvc, awstest.ExampleWebAclID)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestWafListTagsForResourceError(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvcError([]string{"ListTagsForResource"})

	out, err := listTagsForResourceWaf(mockSvc, awstest.ExampleWebAclID)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestWafGetRule(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvc([]string{"GetRule"})

	out, err := getRule(mockSvc, awstest.ExampleWebAclID)
	assert.NotEmpty(t, out)
	assert.NoError(t, err)
}

func TestWafGetRuleError(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvcError([]string{"GetRule"})

	out, err := getRule(mockSvc, awstest.ExampleWebAclID)
	assert.Nil(t, out)
	assert.Error(t, err)
}

func TestWafGetWebAcl(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvc([]string{"GetWebACL"})

	out, err := getWebACL(mockSvc, aws.String("asdfasdf-x123-y123-z123-1234asdf1234"))

	assert.NoError(t, err)
	assert.NotEmpty(t, out)
}

func TestWafGetWebAclError(t *testing.T) {
	mockSvc := awstest.BuildMockWafSvcError([]string{"GetWebACL"})

	out, err := getWebACL(mockSvc, aws.String("asdfasdf-x123-y123-z123-1234asdf1234"))

	assert.Error(t, err)
	assert.Nil(t, out)
}

func TestBuildWafWebAclSnapshot(t *testing.T) {
	mockWafSvc := awstest.BuildMockWafSvcAll()

	wafWebAclSnapshot, err := buildWafWebACLSnapshot(
		mockWafSvc,
		aws.String("asdfasdf-x123-y123-z123-1234asdf1234"),
	)

	assert.NoError(t, err)
	assert.NotEmpty(t, wafWebAclSnapshot.ID)
	assert.NotEmpty(t, wafWebAclSnapshot.DefaultAction)
	assert.NotEmpty(t, wafWebAclSnapshot.Rules)
	assert.IsType(t, &awsmodels.WafRule{}, wafWebAclSnapshot.Rules[0])
	assert.Equal(t, aws.String("112233"), wafWebAclSnapshot.Rules[0].RuleId)
}

func TestBuildWafWebAclSnapshotError(t *testing.T) {
	mockWafSvc := awstest.BuildMockWafSvcAllError()

	wafWebAclSnapshot, err := buildWafWebACLSnapshot(
		mockWafSvc,
		aws.String("asdfasdf-x123-y123-z123-1234asdf1234"),
	)

	assert.Nil(t, wafWebAclSnapshot)
	assert.Error(t, err)
}

func TestWafWebAclsPoller(t *testing.T) {
	awstest.MockWafForSetup = awstest.BuildMockWafSvcAll()
	awstest.MockWafRegionalForSetup = awstest.BuildMockWafRegionalSvcAll()

	WafClientFunc = awstest.SetupMockWaf
	WafRegionalClientFunc = awstest.SetupMockWafRegional

	resources, marker, err := PollWafWebAcls(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NotEmpty(t, resources)
	assert.Equal(t, *awstest.ExampleGetWebAclOutput.WebACL.WebACLArn, resources[0].ID)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestWafWebAclsPollerError(t *testing.T) {
	resetCache()
	awstest.MockWafForSetup = awstest.BuildMockWafSvcAllError()
	awstest.MockWafRegionalForSetup = awstest.BuildMockWafRegionalSvcAllError()

	WafClientFunc = awstest.SetupMockWaf
	WafRegionalClientFunc = awstest.SetupMockWafRegional

	resources, marker, err := PollWafWebAcls(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Nil(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}

func TestWafRegionalWebAclsPoller(t *testing.T) {
	awstest.MockWafForSetup = awstest.BuildMockWafSvcAll()
	awstest.MockWafRegionalForSetup = awstest.BuildMockWafRegionalSvcAll()

	WafClientFunc = awstest.SetupMockWaf
	WafRegionalClientFunc = awstest.SetupMockWafRegional

	resources, marker, err := PollWafRegionalWebAcls(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.NotEmpty(t, resources)
	assert.Equal(t, *awstest.ExampleGetWebAclOutput.WebACL.WebACLArn, resources[0].ID)
	assert.Nil(t, marker)
	assert.NoError(t, err)
}

func TestWafRegionalWebAclsPollerError(t *testing.T) {
	resetCache()
	awstest.MockWafForSetup = awstest.BuildMockWafSvcAllError()
	awstest.MockWafRegionalForSetup = awstest.BuildMockWafRegionalSvcAllError()

	WafClientFunc = awstest.SetupMockWaf
	WafRegionalClientFunc = awstest.SetupMockWafRegional

	resources, marker, err := PollWafRegionalWebAcls(&awsmodels.ResourcePollerInput{
		AuthSource:          &awstest.ExampleAuthSource,
		AuthSourceParsedARN: awstest.ExampleAuthSourceParsedARN,
		IntegrationID:       awstest.ExampleIntegrationID,
		Region:              awstest.ExampleRegion,
		Timestamp:           &awstest.ExampleTime,
	})

	assert.Empty(t, resources)
	assert.Nil(t, marker)
	assert.Error(t, err)
}
