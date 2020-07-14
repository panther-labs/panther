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
	"bytes"
	"io"

	jsoniter "github.com/json-iterator/go"

	"github.com/panther-labs/panther/internal/log_analysis/message_forwarder/forwarder"
)

type MessageForwarderReader struct {
	dec    *jsoniter.Decoder
	buffer bytes.Buffer
}

// Reader for messages sent by the Message Forwarder Lambda
func NewMessageForwarderReader(input io.Reader) *MessageForwarderReader {
	return &MessageForwarderReader{
		dec: jsoniter.NewDecoder(input),
	}
}

func (r *MessageForwarderReader) Read(p []byte) (n int, err error) {
	if len(r.buffer.Bytes()) > 0 {
		return r.buffer.Read(p)
	}
	if err = r.fill(); err != nil {
		return 0, err
	}
	return r.buffer.Read(p)
}

func (r *MessageForwarderReader) fill() error {
	event := forwarder.Message{}
	if !r.dec.More() {
		return io.EOF
	}
	if err := r.dec.Decode(&event); err != nil {
		return err
	}
	if _, err := r.buffer.WriteString(event.Payload + "\n"); err != nil {
		return err
	}
	return nil
}
