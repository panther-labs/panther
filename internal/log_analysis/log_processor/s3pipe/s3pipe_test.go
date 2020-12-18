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
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestDownloadPipe(t *testing.T) {
	for _, tc := range []testCase{
		{"data longer than part size", 1024, 4096, false},
		{"data shorter than part size", 512, 256, false},
		{"data longer than part size, fail", 1026, 4000, true},
		{"half data", 512, 1024, true},
	} {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			expectBody := repeatedLines("foo bar baz", tc.BodySize)
			s3Mock := mockS3(expectBody, tc.PartSize, tc.Fail)
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
			var actual bytes.Buffer
			n, err := actual.ReadFrom(rc)
			assert.NoError(err)
			assert.Equal(int64(len(expectBody)), n)
			assert.Equal(expectBody, actual.Bytes())
			s3Mock.AssertExpectations(t)
		})
	}
}

func TestGunzip(t *testing.T) {
	assert := require.New(t)
	data := "foo bar baz"
	buf := bytes.Buffer{}
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write([]byte(data))
	err := gz.Close()
	assert.NoError(err)
	s3Mock := &testutils.S3Mock{}
	s3Mock.On("MaxRetries").Return(3)
	part, contentRange := bodyPart(buf.Bytes(), 0, 512)
	s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(&s3.GetObjectOutput{
		ContentRange: &contentRange,
		Body:         ioutil.NopCloser(bytes.NewReader(part)),
	}, nil).Once()
	dl := Downloader{
		S3:       s3Mock,
		PartSize: 512,
	}
	input := &s3.GetObjectInput{
		Bucket: aws.String("bucket"),
		Key:    aws.String("key"),
	}
	rc := dl.Download(context.Background(), input)
	defer rc.Close()
	body := bytes.Buffer{}
	_, err = body.ReadFrom(rc)
	assert.NoError(err)
	assert.Equal("foo bar baz", body.String())
	s3Mock.AssertExpectations(t)
}

type testCase struct {
	Name     string
	PartSize int
	BodySize int
	Fail     bool
}

func mockS3(body []byte, partSize int, fail bool) *testutils.S3Mock {
	s3Mock := &testutils.S3Mock{}
	s3Mock.On("MaxRetries").Return(3)
	numParts := numParts(len(body), partSize)
	for i := 0; i < numParts; i++ {
		part, contentRange := bodyPart(body, i, partSize)
		output := s3.GetObjectOutput{
			ContentRange:  aws.String(contentRange),
			ContentLength: aws.Int64(int64(len(part))),
			Body:          ioutil.NopCloser(bytes.NewReader(part)),
		}
		if fail {
			// Copy output
			output := output
			// Set body to failing reader
			output.Body = ioutil.NopCloser(&networkFailReader{})
			s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(&output, nil).Once()
		}
		s3Mock.On("GetObjectWithContext", mock.Anything, mock.Anything, mock.Anything).Return(&output, nil).Once()
	}
	return s3Mock
}

func bodyPart(body []byte, i, partSize int) ([]byte, string) {
	start := i * partSize
	end := start + partSize
	total := len(body)
	if end > total {
		end = total
	}
	return body[start:end], fmt.Sprintf("bytes %d-%d/%d", start, end, total)
}

func numParts(total, part int) int {
	n := total / part
	if total%part != 0 {
		n++
	}
	return n
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

func repeatedLines(line string, maxSize int) (buf []byte) {
	line = strings.TrimRightFunc(line, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	for len(buf) < maxSize {
		if len(buf) != 0 {
			buf = append(buf, '\n')
		}
		buf = append(buf, line...)
	}
	return buf
}

// This test is here to ensure that proper handling of edge cases exists when downloading.
// If edge cases are not handled, reading from the io.ReadCloser might block indefinitely.
// This won't happen every time but it is quite hard to coordinate the goroutines on each run.
// If this test starts randomly failing, someone has messed with the fine balance things in the Downloader.
func TestEarlyClose(t *testing.T) {
	s3Mock := &testutils.S3Mock{}
	s3Mock.On("MaxRetries").Return(3)
	s3Mock.On("GetObjectWithContext",
		mock.Anything, mock.Anything, mock.Anything,
	).Return((*s3.GetObjectOutput)(nil), errors.New("failed")).Once()
	dl := Downloader{
		S3:       s3Mock,
		PartSize: 32,
	}
	rc := dl.Download(context.Background(), &s3.GetObjectInput{})
	rc.Close()
	buf := bytes.Buffer{}
	n, err := buf.ReadFrom(rc)
	require.Error(t, err)
	require.Equal(t, int64(0), n)
	s3Mock.AssertExpectations(t)
}

func TestCopyBuffersHandlesClosedChannel(t *testing.T) {
	ch := make(chan *bytes.Buffer)
	close(ch)
	r, w := io.Pipe()
	peekCalled := false
	peek := func(buf []byte) {
		if buf == nil {
			peekCalled = true
		}
	}
	require.NoError(t, r.CloseWithError(errors.New("failed")))
	copyBuffers(w, ch, peek)
	data, err := ioutil.ReadAll(r)
	require.True(t, peekCalled)
	require.Error(t, err)
	require.Equal(t, 0, len(data))
}
