package sources

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
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/api/lambda/source/models"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/logtypes"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/gitlablogs"
)

func TestSQSClassifier(t *testing.T) {
	const (
		testLogType     = "testLog"
		testBucket      = "testBucket"
		testSourceID    = "testSource"
		testSourceLabel = "testSourceLabel"
	)
	testSource := &models.SourceIntegration{
		SourceIntegrationMetadata: models.SourceIntegrationMetadata{
			IntegrationID:    testSourceID,
			IntegrationLabel: testSourceLabel,
			IntegrationType:  models.IntegrationTypeSqs,
			SqsConfig: &models.SqsConfig{
				LogTypes: []string{testLogType},
				S3Bucket: testBucket,
			},
		},
	}

	testGroup := logtypes.Must("test", logtypes.ConfigJSON{
		Name:         testLogType,
		Description:  "Test log type",
		ReferenceURL: "-",
		NewEvent: func() interface{} {
			return &gitlablogs.API{}
		},
	})
	// nolint:lll
	logData := `{"payload":"{\"severity\":\"INFO\",\"duration_s\":0.01524,\"db_duration_s\":0.00314,\"view_duration_s\":0.0121,\"status\":200,\"method\":\"POST\",\"path\":\"/api/v4/internal/post_receive\",\"params\":[{\"key\":\"gl_repository\",\"value\":\"project-9\"},{\"key\":\"identifier\",\"value\":\"user-2\"},{\"key\":\"changes\",\"value\":\"557fb80351047f0f65b4a4d8dd5d5ef07b95dcc9 7e4aac7b6bf60c74d0571d30b0ac6a19c76a9be4 refs/heads/master\\n\"},{\"key\":\"secret_token\",\"value\":\"[FILTERED]\"}],\"host\":\"127.0.0.1\",\"remote_ip\":\"127.0.0.1\",\"ua\":\"Ruby\",\"route\":\"/api/:version/internal/post_receive\",\"redis_calls\":10,\"redis_duration_s\":0.000738,\"correlation_id\":\"895c51dc-96c8-4f18-8be4-65252b17a324\",\"meta.user\":\"testuser\",\"meta.project\":\"testuser/jumbotron\",\"meta.root_namespace\":\"testuser\",\"meta.caller_id\":\"/api/:version/internal/post_receive\",\"tag\":\"gitlab.poc.api\",\"time\":\"2018-10-29T12:49:42.123Z\"}","sourceId":"testSource"}
`
	c := SQSClassifier{
		Resolver: logtypes.ParserResolver(logtypes.LocalResolver(testGroup)),
		LoadSource: func(id string) (*models.SourceIntegration, error) {
			if id == testSourceID {
				return testSource, nil
			}
			return nil, errors.New("source not found")
		},
	}
	result, err := c.Classify(logData)
	require.NoError(t, err)
	require.NotNil(t, result)
}
