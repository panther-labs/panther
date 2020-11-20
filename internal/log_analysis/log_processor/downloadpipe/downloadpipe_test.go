package downloadpipe

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
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/pkg/testutils"
)

func TestDownloadPipe(t *testing.T) {
	downloader := &s3manager.Downloader{
		PartSize:    DownloadPartSize,
		Concurrency: 1,
	}

	var dataWritten []byte

	// case: data smaller than d.PartSize
	dataWritten = []byte("small")
	doPipe(t, downloader, dataWritten, "smaller")

	// case: data larger than d.PartSize
	dataWritten = []byte("two writes")
	downloader.PartSize = int64(len(dataWritten)/2) + 1
	doPipe(t, downloader, dataWritten, "larger")
}

func doPipe(t *testing.T, downloader *s3manager.Downloader, dataWritten []byte, testName string) *bytes.Buffer {
	var dataRead bytes.Buffer
	var wg sync.WaitGroup

	getObjectInput := &s3.GetObjectInput{
		Bucket: aws.String("bucket"),
		Key:    aws.String("key"),
	}

	downloadPipe := NewDownloadPipe(&testutils.S3Mock{}, getObjectInput)
	wg.Add(1)
	go func() {
		defer wg.Done()
		var n int
		var err error

		// this simulates the downloader
		for i := 0; i < len(dataWritten); i += n {
			extent := len(dataWritten) - n
			if extent > int(downloader.PartSize) {
				extent = int(downloader.PartSize)
			}
			n, err = downloadPipe.WriteAt(dataWritten[i:i+extent], int64(i))
			require.NoError(t, err)
		}
		err = downloadPipe.CloseWriter()
		require.NoError(t, err)
	}()
	wg.Add(1)
	go func() { // drain
		defer wg.Done()
		var err error
		var n int64 = -1

		for n != 0 {
			n, err = dataRead.ReadFrom(downloadPipe)
			require.NoError(t, err)
		}
	}()
	wg.Wait()

	assert.Equal(t, string(dataWritten), dataRead.String(), testName)

	return &dataRead
}
