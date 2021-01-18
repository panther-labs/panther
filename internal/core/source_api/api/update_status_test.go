package api

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/core/source_api/ddb"
	"github.com/panther-labs/panther/pkg/testutils"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAPI_UpdateStatus_FailsIfIntegrationNotExists(t *testing.T) {
	testutils.IntegrationTest(t) // test runs the API handler locally but hits a real DynamoDB

	awsSession := session.Must(session.NewSession())
	testAPI := &API{
		AwsSession: awsSession,
		DdbClient:  ddb.New(awsSession, "panther-source-integrations"),
	}

	input := models.UpdateStatusInput{
		IntegrationID:     "abcdefgh-abcd-abcd-abcd-abcdefghijkl",
		LastEventReceived: time.Now(),
	}
	err := testAPI.UpdateStatus(&input)

	require.Error(t, err)
}
