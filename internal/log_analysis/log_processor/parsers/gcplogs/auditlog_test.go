package gcplogs

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
	"time"

	"github.com/aws/aws-sdk-go/aws"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/testutil"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers/timestamp"
)

func TestAuditLogParser(t *testing.T) {
	log := `{
		"protoPayload": {
			"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
			"authenticationInfo": {
				"principalEmail": "system:serviceaccount:monitoring:prometheus-k8s"
			},
			"authorizationInfo": [
				{
					"granted": true,
					"permission": "io.k8s.core.v1.nodes.proxy.get",
					"resource": "core/v1/nodes/gke-adx-default-pool-e05a7794-jgln/proxy/metrics/cadvisor"
				}
			],
			"methodName": "io.k8s.core.v1.nodes.proxy.get",
			"requestMetadata": {
				"callerIp": "35.238.150.117",
				"callerSuppliedUserAgent": "Prometheus/1.8.2"
			},
			"resourceName": "core/v1/nodes/gke-adx-default-pool-e05a7794-jgln/proxy/metrics/cadvisor",
			"serviceName": "k8s.io",
			"status": {
				"code": 0
			}
		},
		"insertId": "dc7605e6-1e19-4571-8a7a-d23682efcea1",
		"resource": {
			"type": "k8s_cluster",
			"labels": {
			"project_id": "some-project-id",
			"cluster_name": "the-cluster",
			"location": "us-central1-f"
			}
		},
		"timestamp": "2020-04-24T06:29:54.304506Z",
		"labels": {
			"authorization.k8s.io/reason": "",
			"authorization.k8s.io/decision": "allow"
		},
		"logName": "projects/some-project-id/logs/cloudaudit.googleapis.com%2Factivity",
		"operation": {
			"id": "dc7605e6-1e19-4571-8a7a-d23682efcea1",
			"producer": "k8s.io",
			"first": true
		},
		"receiveTimestamp": "2020-04-24T06:29:54.502612236Z"
	}`

	ts, err := time.Parse(time.RFC3339Nano, "2020-04-24T06:29:54.304506Z")
	if err != nil {
		t.Fatal(err)
	}
	tsReceive, err := time.Parse(time.RFC3339Nano, "2020-04-24T06:29:54.502612236Z")
	if err != nil {
		t.Fatal(err)
	}

	entry := &LogEntryAuditLog{
		LogEntry: LogEntry{
			LogName:          aws.String("projects/some-project-id/logs/cloudaudit.googleapis.com%2Factivity"),
			Timestamp:        (*timestamp.RFC3339)(&ts),
			ReceiveTimestamp: (*timestamp.RFC3339)(&tsReceive),
			Labels: Labels{
				"authorization.k8s.io/reason":   "",
				"authorization.k8s.io/decision": "allow",
			},
			InsertID: aws.String("dc7605e6-1e19-4571-8a7a-d23682efcea1"),
			Resource: MonitoredResource{
				Type: aws.String("k8s_cluster"),
				Labels: Labels{
					"project_id":   "some-project-id",
					"cluster_name": "the-cluster",
					"location":     "us-central1-f",
				},
			},
			Operation: &LogEntryOperation{
				ID:       aws.String("dc7605e6-1e19-4571-8a7a-d23682efcea1"),
				Producer: aws.String("k8s.io"),
				First:    aws.Bool(true),
			},
		},
		Payload: AuditLog{
			PayloadType: aws.String("type.googleapis.com/google.cloud.audit.AuditLog"),
			AuthenticationInfo: &AuthenticationInfo{
				PrincipalEmail: aws.String("system:serviceaccount:monitoring:prometheus-k8s"),
			},
			AuthorizationInfo: []AuthorizationInfo{
				{
					Granted:    aws.Bool(true),
					Permission: aws.String("io.k8s.core.v1.nodes.proxy.get"),
					Resource:   aws.String("core/v1/nodes/gke-adx-default-pool-e05a7794-jgln/proxy/metrics/cadvisor"),
				},
			},
			MethodName: aws.String("io.k8s.core.v1.nodes.proxy.get"),
			RequestMetadata: &RequestMetadata{
				CallerIP:                aws.String("35.238.150.117"),
				CallerSuppliedUserAgent: aws.String("Prometheus/1.8.2"),
			},
			ResourceName: aws.String("core/v1/nodes/gke-adx-default-pool-e05a7794-jgln/proxy/metrics/cadvisor"),
			ServiceName:  aws.String("k8s.io"),
			Status: &Status{
				Code: aws.Int32(0),
			},
		},
	}

	entry.SetCoreFields(TypeAuditLogActivity, entry.Timestamp, entry)
	entry.AppendAnyIPAddress("35.238.150.117")
	testutil.CheckPantherParser(t, log, NewAuditLogActivityParser(), &entry.PantherLog)
}
