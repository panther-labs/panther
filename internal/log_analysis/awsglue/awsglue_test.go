package awsglue

import (
	"github.com/panther-labs/panther/internal/log_analysis/pantherdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTypesFromS3Key(t *testing.T) {

	// fail
	_, _, err := TypesFromS3Key("")
	require.Error(t, err)

	// log
	dataType, logType,  err := TypesFromS3Key("logs/aws_cloudtrail")
	require.NoError(t, err)
	assert.Equal(t,  pantherdb.LogData, dataType)
	assert.Equal(t, logType, "AWS.CloudTrail")
}

