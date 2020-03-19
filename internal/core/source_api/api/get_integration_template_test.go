package api

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/pkg/testutils"
)

func TestLogAnalysisTemplate(t *testing.T) {
	s3Mock := &testutils.S3Mock{}
	s3Client = s3Mock
	input := &models.GetIntegrationTemplateInput{
		AWSAccountID:       aws.String("123456789012"),
		IntegrationType:    aws.String(models.IntegrationTypeAWS3),
		IntegrationLabel:   aws.String("TestLabel-"),
		S3Bucket:           aws.String("test-bucket"),
		S3Prefix:           aws.String("prefix"),
		KmsKey:             aws.String("key-arn"),
	}

	template, err := ioutil.ReadFile("../../../../deployments/auxiliary/cloudformation/panther-log-processing-iam.yml")
	require.NoError(t, err)
	s3Mock.On("GetObject", mock.Anything).Return(&s3.GetObjectOutput{Body:ioutil.NopCloser(bytes.NewReader(template))}, nil)


	result, err := API{}.GetIntegrationTemplate(input)

	require.NoError(t, err)
	expectedTemplate, err := ioutil.ReadFile("./testdata/panther-log-processing-iam-updated.yml")
	require.NoError(t, err)
	require.Equal(t, string(expectedTemplate), *result.Body)
}
