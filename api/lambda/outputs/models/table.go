package models

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

// AlertOutputItem is the output configuration stored in DynamoDB.
type AlertOutputItem struct {

	// The user ID of the user that created the alert output
	CreatedBy *string `json:"createdBy"`

	// The time in epoch seconds when the alert output was created
	CreationTime *string `json:"creationTime"`

	// DisplayName is the user-provided name, e.g. "alert-channel".
	DisplayName *string `json:"displayName"`

	// EncryptedConfig is the encrypted JSON of the specific output details.
	EncryptedConfig []byte `json:"encryptedConfig"`

	// The user ID of the user that last modified the alert output last
	LastModifiedBy *string `json:"lastModifiedBy"`

	// The time in epoch seconds when the alert output was last modified
	LastModifiedTime *string `json:"lastModifiedTime"`

	// Identifies uniquely an alert output (table sort key)
	OutputID *string `json:"outputId"`

	// OutputType is the output class, e.g. "slack", "sns".
	// ("type" is a reserved Dynamo keyword, so we use "OutputType" instead)
	OutputType *string `json:"outputType"`

	// VerificationStatus is the current state of the output destination.
	// When an AlertOutput is not in 'VERIFIED' state it cannot be used to send notifications
	VerificationStatus *string `json:"verificationStatus"`
}

// DefaultOutputsItem is the default output configuration stored in DynamoDB.
type DefaultOutputsItem struct {

	//The severity of the (table sort key)
	Severity *string `json:"severity"`

	// Identifies uniquely an alert output
	OutputIDs []*string `json:"outputIds" dynamodbav:"outputIds,stringset"`
}
