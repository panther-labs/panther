package outputs

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
	"github.com/stretchr/testify/mock"

	alertModel "github.com/panther-labs/panther/internal/core/alert_delivery/models"
)

func init() {
	policyURLPrefix = "https://panther.io/policies/"
	alertURLPrefix = "https://panther.io/alerts/"
}

type mockHTTPWrapper struct {
	HTTPWrapper
	mock.Mock
}

func (m *mockHTTPWrapper) post(postInput *PostInput) *AlertDeliveryError {
	args := m.Called(postInput)
	return args.Get(0).(*AlertDeliveryError)
}

func TestGenerateAlertTitleReturnGivenTitle(t *testing.T) {
	alert := &alertModel.Alert{
		Title: aws.String("my title"),
	}

	assert.Equal(t, "New Alert: my title", generateAlertTitle(alert))
}

func TestGenerateAlertTitleRulePolicyName(t *testing.T) {
	alert := &alertModel.Alert{
		Type:         alertModel.RuleType,
		AnalysisName: aws.String("rule name"),
	}
	assert.Equal(t, "New Alert: rule name", generateAlertTitle(alert))
}

func TestGenerateAlertTitleRulePolicyId(t *testing.T) {
	alert := &alertModel.Alert{
		Type:         alertModel.RuleType,
		AnalysisName: aws.String("rule.id"),
	}
	assert.Equal(t, "New Alert: rule.id", generateAlertTitle(alert))
}

func TestGenerateAlertTitlePolicyName(t *testing.T) {
	alert := &alertModel.Alert{
		Type:         alertModel.PolicyType,
		AnalysisName: aws.String("policy name"),
	}
	assert.Equal(t, "Policy Failure: policy name", generateAlertTitle(alert))
}

func TestGenerateAlertTitlePolicyId(t *testing.T) {
	alert := &alertModel.Alert{
		Type:         alertModel.PolicyType,
		AnalysisName: aws.String("policy.id"),
	}
	assert.Equal(t, "Policy Failure: policy.id", generateAlertTitle(alert))
}
