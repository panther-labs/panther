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
	"io"
	"io/ioutil"
	"net"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestDownloadPipe(t *testing.T) {
	var pipeReader io.ReadCloser
	var partSize int
	var dataWritten []byte

	MinPartSize = 1 // so we can force scenarios

	mockS3Client := &testutils.S3Mock{
		Retries: 3,
	}
	getObjectInput := &s3.GetObjectInput{
		Bucket: aws.String("bucket"),
		Key:    aws.String("key"),
	}

	// case: data smaller than partSize
	dataWritten = []byte("small")
	partSize = len(dataWritten) * 2
	pipeReader = NewReader(context.TODO(), getObjectInput, mockS3Client, partSize)
	doPipe(t, mockS3Client, pipeReader, dataWritten, partSize, false, "smaller")

	// case: data larger than partSize
	dataWritten = []byte("three writes")
	partSize = (len(dataWritten) / 3) + 1
	pipeReader = NewReader(context.TODO(), getObjectInput, mockS3Client, partSize)
	doPipe(t, mockS3Client, pipeReader, dataWritten, partSize, false, "larger")

	// same as above but fail once for each GetObject
	dataWritten = []byte("three writes")
	partSize = (len(dataWritten) / 3) + 1
	pipeReader = NewReader(context.TODO(), getObjectInput, mockS3Client, partSize)
	// FIXME: this does not work, read failures are supposed to be retried
	doPipe(t, mockS3Client, pipeReader, dataWritten, partSize, true, "fail")
}

func doPipe(t *testing.T, s3Mock *testutils.S3Mock, pipeReader io.ReadCloser,
	dataWritten []byte, partSize int, fail bool, testName string) {
	defer pipeReader.Close()

	fullPartsToWrite := len(dataWritten) / partSize
	for i := 0; i < fullPartsToWrite; i++ {
		objectData := dataWritten[i*partSize : (i+1)*partSize]
		contentRange := fmt.Sprintf("bytes %d-%d/%d", i*partSize, ((i+1)*partSize)-1, len(dataWritten))
		getObjectOutput := &s3.GetObjectOutput{
			ContentRange:  aws.String(contentRange),
			ContentLength: aws.Int64(int64(len(objectData))),
			Body:          ioutil.NopCloser(bytes.NewReader(objectData)),
		}
		if fail {
			failedGetObjectOutput := &s3.GetObjectOutput{
				ContentRange:  aws.String(contentRange),
				ContentLength: aws.Int64(int64(len(objectData))),
				Body:          ioutil.NopCloser(&networkFailReader{}),
			}
			s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(failedGetObjectOutput,
				nil).Once()
		}
		s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(getObjectOutput, nil).Once()
	}
	if len(dataWritten) != (fullPartsToWrite * partSize) {
		objectData := dataWritten[fullPartsToWrite*partSize:]
		contentRange := fmt.Sprintf("bytes %d-%d/%d", fullPartsToWrite*partSize, len(dataWritten)-1, len(dataWritten))
		getObjectOutput := &s3.GetObjectOutput{
			ContentRange:  aws.String(contentRange),
			ContentLength: aws.Int64(int64(len(objectData))),
			Body:          ioutil.NopCloser(bytes.NewReader(objectData)),
		}
		if fail {
			failedGetObjectOutput := &s3.GetObjectOutput{
				ContentRange:  aws.String(contentRange),
				ContentLength: aws.Int64(int64(len(objectData))),
				Body:          ioutil.NopCloser(&networkFailReader{}),
			}
			s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(failedGetObjectOutput,
				nil).Once()
		}
		s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(getObjectOutput, nil).Once()
	}

	var dataRead bytes.Buffer
	for {
		n, err := dataRead.ReadFrom(pipeReader)
		require.NoError(t, err)
		if n == 0 {
			break
		}
	}

	assert.Equal(t, string(dataWritten), dataRead.String(), testName)
	s3Mock.AssertExpectations(t)
}

type networkFailReader struct{}

func (*networkFailReader) Read(_ []byte) (n int, err error) {
	netErr := net.OpError{
		Op:     "read",
		Net:    "foo",
		Source: nil,
		Addr:   nil,
		Err:    errors.New("connection reset by peer"),
	}
	return 0, &netErr
}
