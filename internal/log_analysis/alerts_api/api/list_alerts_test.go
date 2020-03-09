package api

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/alerts/models"
	"github.com/panther-labs/panther/internal/log_analysis/alerts_api/table"
)

var (
	timeInTest = time.Now()

	alertItems = []*table.AlertItem {
		{
			RuleID: "ruleId",
			AlertID: "alertId",
			UpdateTime: timeInTest,
			CreationTime: timeInTest,
			Severity: "INFO",
			DedupString: "dedupString",
			LogTypes: []string{"AWS.CloudTrail"},
			EventCount: 100,
		},
	}

	expectedAlertSummary = []*models.AlertSummary {
		{
			RuleID: aws.String("ruleId"),
			AlertID: aws.String("alertId"),
			UpdateTime: aws.Time(timeInTest),
			CreationTime: aws.Time(timeInTest),
			Severity: aws.String("INFO"),
			DedupString: aws.String("dedupString"),
			EventsMatched: aws.Int(100),
		},
	}
)

func TestListAlertsForRule(t *testing.T)  {
	tableMock := &tableMock{}
	alertsDB = tableMock

	input := &models.ListAlertsInput{
		RuleID:            aws.String("ruleId"),
		PageSize:          aws.Int(10),
		ExclusiveStartKey: aws.String("startKey"),
	}

	tableMock.On("ListByRule", "ruleId", aws.String("startKey"), aws.Int(10)).
		Return(alertItems, aws.String("lastKey"), nil)
	result, err := API{}.ListAlerts(input)
	require.NoError(t, err)

	assert.Equal(t, &models.ListAlertsOutput{
		Alerts:           expectedAlertSummary,
		LastEvaluatedKey: aws.String("lastKey"),
	}, result)
}

func TestListAllAlerts(t *testing.T)  {
	tableMock := &tableMock{}
	alertsDB = tableMock

	input := &models.ListAlertsInput{
		PageSize:          aws.Int(10),
		ExclusiveStartKey: aws.String("startKey"),
	}

	tableMock.On("ListAll", aws.String("startKey"), aws.Int(10)).
		Return(alertItems, aws.String("lastKey"), nil)
	result, err := API{}.ListAlerts(input)
	require.NoError(t, err)

	assert.Equal(t, &models.ListAlertsOutput{
		Alerts:           expectedAlertSummary,
		LastEvaluatedKey: aws.String("lastKey"),
	}, result)
}
