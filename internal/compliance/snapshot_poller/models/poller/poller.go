package poller

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

// ScanMsg contains a list of Scan Entries.
type ScanMsg struct {
	Entries []*ScanEntry `json:"entries"`
}

// ScanEntry indicates what type of scan should be performed, and provides the information needed
// to carry out that scan.
// The poller can scan a single resource, all resources of a given type, or all resources.
// Scanning all resources in an account is discouraged for performance reasons.
type ScanEntry struct {
	AWSAccountID  *string `json:"awsAccountId"`
	IntegrationID *string `json:"integrationId"`
	Region        *string `json:"region"`
	ResourceID    *string `json:"resourceId"`
	ResourceType  *string `json:"resourceType"`
	NextPageToken *string `json:"nextPageToken"`
}
