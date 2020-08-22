package api

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
	"testing"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/stretchr/testify/assert"
)

func TestGetSQSClient(t *testing.T) {
	assert.NotNil(t, getSQSClient())
}

// 95 ms / op
func BenchmarkSessionCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		session.Must(session.NewSession())
	}
}

// 2.7 ms / op
func BenchmarkClientCreation(b *testing.B) {
	sess := session.Must(session.NewSession())
	for i := 0; i < b.N; i++ {
		sqs.New(sess)
	}
}
