package aws

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
	"time"

	"github.com/aws/aws-sdk-go/service/iam"
)

const (
	// IAMRootUserSchema is the schema identifier for IAMRootUser.
	IAMRootUserSchema = "AWS.IAM.RootUser"
	// IAMUserSchema is the schema identifier for IAMUser.
	IAMUserSchema = "AWS.IAM.User"
)

// IAMUser contains all information about an IAM User
type IAMUser struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Fields embedded from iam.User
	PasswordLastUsed    *time.Time
	Path                *string
	PermissionsBoundary *iam.AttachedPermissionsBoundary

	// Additional fields
	CredentialReport   *IAMCredentialReport
	Groups             []*iam.Group
	InlinePolicies     map[string]*string
	ManagedPolicyNames []*string
	VirtualMFA         *VirtualMFADevice
}

// IAMRootUser extends IAMUser, and contains some additional
// information only pertinent to the root account.
type IAMRootUser struct {
	// Generic resource fields
	GenericAWSResource
	GenericResource

	// Additional fields
	CredentialReport *IAMCredentialReport
	VirtualMFA       *VirtualMFADevice
}

// IAMCredentialReport provides information on IAM credentials in an AWS Account.
//
// This includes status of credentials, console passwords, access keys, MFA devices, and more.
type IAMCredentialReport struct {
	UserName                  *string
	ARN                       *string
	UserCreationTime          *time.Time
	PasswordEnabled           *bool
	PasswordLastUsed          *time.Time
	PasswordLastChanged       *time.Time
	PasswordNextRotation      *time.Time
	MfaActive                 *bool
	AccessKey1Active          *bool
	AccessKey1LastRotated     *time.Time
	AccessKey1LastUsedDate    *time.Time
	AccessKey1LastUsedRegion  *string
	AccessKey1LastUsedService *string
	AccessKey2Active          *bool
	AccessKey2LastRotated     *time.Time
	AccessKey2LastUsedDate    *time.Time
	AccessKey2LastUsedRegion  *string
	AccessKey2LastUsedService *string
	Cert1Active               *bool
	Cert1LastRotated          *time.Time
	Cert2Active               *bool
	Cert2LastRotated          *time.Time
}

// VirtualMFADevice provides metadata about an IAM User's MFA device
type VirtualMFADevice struct {
	EnableDate   *time.Time
	SerialNumber *string
}
