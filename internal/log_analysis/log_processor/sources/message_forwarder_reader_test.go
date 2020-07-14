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
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	forwarderMessagePayload = "test"
	forwarderMessageSample  = fmt.Sprintf(`{"payload": "%s", "sourceId": "c08e3245-5251-4d72-b9da-46f6b6ac7b30"}`,
		forwarderMessagePayload)
)

func TestReadForwarderMessage(t *testing.T) {
	reader := NewMessageForwarderReader(strings.NewReader(forwarderMessageSample + "\n"))

	result, err := ioutil.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, forwarderMessagePayload+"\n", string(result))
}

func TestReadForwarderMessages(t *testing.T) {
	reader := NewMessageForwarderReader(strings.NewReader(forwarderMessageSample + "\n" + forwarderMessageSample + "\n"))

	bufferedReader := bufio.NewReader(reader)
	line, err := bufferedReader.ReadString('\n')
	require.Equal(t, forwarderMessagePayload+"\n", line)
	require.NoError(t, err)

	line, err = bufferedReader.ReadString('\n')
	require.Equal(t, forwarderMessagePayload+"\n", line)
	require.Error(t, io.EOF, err)
}

func TestReadForwarderInvalidJson(t *testing.T) {
	reader := NewMessageForwarderReader(strings.NewReader("{'test':1"))
	buffer := make([]byte, 10)

	bytesRead, err := reader.Read(buffer)

	require.Equal(t, 0, bytesRead)
	require.Error(t, io.EOF, err)
	require.Equal(t, buffer, make([]byte, 10))
}

func TestReadForwarderEmptyString(t *testing.T) {
	reader := NewMessageForwarderReader(strings.NewReader(""))

	buffer := make([]byte, 10)
	bytesRead, err := reader.Read(buffer)
	require.Equal(t, 0, bytesRead)
	require.Error(t, io.EOF, err)
	require.Equal(t, buffer, make([]byte, 10))
}

func TestReadForwarderMessagePartialRead(t *testing.T) {
	reader := NewMessageForwarderReader(strings.NewReader(forwarderMessageSample + "\n"))

	// make the buffer intentionally smaller
	// so that we need to invoke the reader twice
	truncatedPayloadSize := len(forwarderMessagePayload) - 1
	buffer := make([]byte, truncatedPayloadSize)

	// should read payload partially
	bytesRead, err := reader.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, truncatedPayloadSize, bytesRead)
	require.Equal(t, forwarderMessagePayload[:truncatedPayloadSize], string(buffer))

	// clear the buffer
	buffer = make([]byte, 2)
	// should read remaining
	bytesRead, err = reader.Read(buffer)
	require.NoError(t, err)
	require.Equal(t, 2, bytesRead)
	require.Equal(t, forwarderMessagePayload[truncatedPayloadSize:]+"\n", string(buffer))

	// clear the buffer
	buffer = make([]byte, 1)

	bytesRead, err = reader.Read(buffer)
	require.Error(t, io.EOF, err)
	require.Equal(t, 0, bytesRead)
}
