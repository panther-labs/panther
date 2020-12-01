package s3pipe

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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestDownloadPipe(t *testing.T) {
	for _, tc := range []testCase{
		{"data shorter than part size", 12, []byte("small"), false},
		{"data longer than part size", 4, []byte("foo bar baz qux"), false},
		{"data longer than part size, fail", 4, []byte("foo bar baz qux"), true},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			s3Mock := tc.mockS3()
			dl := Downloader{
				S3:       s3Mock,
				PartSize: int64(tc.PartSize),
			}
			input := &s3.GetObjectInput{
				Bucket: aws.String("bucket"),
				Key:    aws.String("key"),
			}
			rc := dl.Download(context.Background(), input)
			defer rc.Close()

			assert := require.New(t)
			var body bytes.Buffer
			n, err := body.ReadFrom(rc)
			assert.NoError(err)
			assert.Equal(n, int64(len(tc.Data)))
			assert.Equal(tc.Data, body.Bytes())
			s3Mock.AssertExpectations(t)
		})
	}
}

type testCase struct {
	Name     string
	PartSize int
	Data     []byte
	Fail     bool
}

func (tc testCase) mockS3() *testutils.S3Mock {
	s3Mock := testutils.S3Mock{
		Retries: 3,
	}
	for i := 0; i <= tc.numParts(); i++ {
		data, contentRange := tc.bodyPart(i)
		output := s3.GetObjectOutput{
			ContentRange:  aws.String(contentRange),
			ContentLength: aws.Int64(int64(len(data))),
			Body:          ioutil.NopCloser(bytes.NewReader(data)),
		}
		if tc.Fail {
			// Copy output
			output := output
			// Set body to failing reader
			output.Body = ioutil.NopCloser(&networkFailReader{})
			s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(&output, nil).Once()
		}
		s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(&output, nil).Once()
	}
	return &s3Mock
}
func (tc testCase) bodyPart(i int) ([]byte, string) {
	start := i * tc.PartSize
	end := start + tc.PartSize
	total := len(tc.Data)
	if end > total {
		end = total
	}
	return tc.Data[start:end], fmt.Sprintf("bytes %d-%d/%d", start, end, total)
}

func (tc testCase) numParts() int {
	return len(tc.Data) / tc.PartSize
}

type networkFailReader struct{}

func (*networkFailReader) Read(p []byte) (int, error) {
	netErr := net.OpError{
		Op:     "read",
		Net:    "foo",
		Source: nil,
		Addr:   nil,
		Err:    errors.New("connection reset by peer"),
	}
	// Make sure to returned some partial data.
	return copy(p, "FAIL"), &netErr
}
