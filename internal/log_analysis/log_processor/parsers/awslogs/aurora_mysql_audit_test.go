package awslogs

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/stretchr/testify/require"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestAuroraMySQLAuditLog(t *testing.T) {
	//nolint:lll
	log := "1572546356975302,db-instance-name,someuser,10.0.143.147,1688069,168876953,QUERY,testdb," +
		"'select `user_id` as `userId`, `address`, `type`, `access`, `ordinal`, `token`, `verified`, `organization_id` as `organizationId`, `expires_at` as `expiresAt`, `created_at` as `createdAt`, `updated_at` as `updatedAt` " +
		"from `address_verification` where `ordinal` = \\'primary\\' and `access` = \\'public\\' and `type` = \\'phoneNumber\\' and `verified` = true and `user_id` = \\'12345678-8a3b-4d3f-96a7-19cc4c58c25d\\'',0"

	expectedTime := time.Unix(1572546356, 975302000).UTC()
	expectedEvent := &AuroraMySQLAudit{
		Timestamp:    (*timestamp.RFC3339)(&expectedTime),
		ServerHost:   aws.String("db-instance-name"),
		Username:     aws.String("someuser"),
		Host:         aws.String("10.0.143.147"),
		ConnectionID: aws.Int(1688069),
		QueryID:      aws.Int(168876953),
		Operation:    aws.String("QUERY"),
		Database:     aws.String("testdb"),
		//nolint:lll
		Object:  aws.String("'select `user_id` as `userId`, `address`, `type`, `access`, `ordinal`, `token`, `verified`, `organization_id` as `organizationId`, `expires_at` as `expiresAt`, `created_at` as `createdAt`, `updated_at` as `updatedAt` from `address_verification` where `ordinal` = \\'primary\\' and `access` = \\'public\\' and `type` = \\'phoneNumber\\' and `verified` = true and `user_id` = \\'12345678-8a3b-4d3f-96a7-19cc4c58c25d\\''"),
		RetCode: aws.Int(0),
	}

	// panther fields
	expectedEvent.PantherLogType = aws.String("AWS.AuroraMySQLAudit")
	expectedEvent.PantherEventTime = (*timestamp.RFC3339)(&expectedTime)
	expectedEvent.AppendAnyIPAddresses("10.0.143.147")
	expectedEvent.AppendAnyDomainNames("db-instance-name")

	checkAuroraMysqlAuditLogLog(t, log, expectedEvent)
}

func TestAuroraMysqlAuditLogType(t *testing.T) {
	parser := &AuroraMySQLAuditParser{}
	require.Equal(t, "AWS.AuroraMySQLAudit", parser.LogType())
}

func checkAuroraMysqlAuditLogLog(t *testing.T, log string, expectedEvent *AuroraMySQLAudit) {
	parser := &AuroraMySQLAuditParser{}
	testutil.EqualPantherLog(t, expectedEvent.Log(), parser.Parse(log))
}
