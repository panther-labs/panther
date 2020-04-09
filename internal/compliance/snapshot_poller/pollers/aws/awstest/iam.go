package awstest

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
	"errors"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/stretchr/testify/mock"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

var (

	//
	// Example IAM PasswordPolicy
	//

	ExamplePasswordPolicy = &iam.PasswordPolicy{
		AllowUsersToChangePassword: aws.Bool(true),
		ExpirePasswords:            aws.Bool(true),
		HardExpiry:                 aws.Bool(false),
		MaxPasswordAge:             aws.Int64(80),
		MinimumPasswordLength:      aws.Int64(12),
		PasswordReusePrevention:    aws.Int64(10),
		RequireLowercaseCharacters: aws.Bool(true),
		RequireNumbers:             aws.Bool(true),
		RequireSymbols:             aws.Bool(true),
		RequireUppercaseCharacters: aws.Bool(true),
	}

	ExamplePasswordPolicyOutput = &iam.GetAccountPasswordPolicyOutput{
		PasswordPolicy: ExamplePasswordPolicy,
	}

	//
	// Example IAM Credential Report
	//

	ExampleCredentialReport = &iam.GetCredentialReportOutput{
		Content:       []byte("user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated\nFranklin,arn:aws:iam::123456789012:user/Franklin,2019-04-01T23:51:37+00:00,not_supported,2019-04-02T17:16:30+00:00,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\n<root_account>,arn:aws:iam::123456789012:root,2019-04-02T17:16:30+00:00,not_supported,2019-04-02T17:16:30+00:00,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A\nunit_test_user,arn:aws:iam::123456789012:user/unit_test_user,2018-12-18T23:44:51+00:00,TRUE,2019-05-30T15:40:58+00:00,2019-04-03T15:16:13+00:00,2019-07-02T15:16:13+00:00,TRUE,TRUE,2019-05-29T23:36:39+00:00,2019-05-30T20:14:00+00:00,us-east-1,sts,FALSE,2019-04-02T20:45:11+00:00,2019-05-29T20:33:00+00:00,us-east-1,sts,FALSE,N/A,FALSE,N/A"),
		GeneratedTime: ExampleDate,
		ReportFormat:  aws.String("text/csv"),
	}

	ExampleExtractedCredentialReport = map[string]*awsmodels.IAMCredentialReport{
		"<root_account>": {
			UserName:                  aws.String("<root_account>"),
			ARN:                       aws.String("arn:aws:iam::123456789012:root"),
			UserCreationTime:          aws.Time(utils.ParseTimeRFC3339("2019-04-02T17:16:30+00:00")),
			PasswordEnabled:           aws.Bool(false),
			PasswordLastUsed:          aws.Time(utils.ParseTimeRFC3339("2019-04-02T17:16:30+00:00")),
			PasswordLastChanged:       aws.Time(time.Time{}),
			PasswordNextRotation:      aws.Time(time.Time{}),
			MfaActive:                 aws.Bool(false),
			AccessKey1Active:          aws.Bool(false),
			AccessKey1LastRotated:     aws.Time(time.Time{}),
			AccessKey1LastUsedDate:    aws.Time(time.Time{}),
			AccessKey1LastUsedRegion:  aws.String("N/A"),
			AccessKey1LastUsedService: aws.String("N/A"),
			AccessKey2Active:          aws.Bool(false),
			AccessKey2LastRotated:     aws.Time(time.Time{}),
			AccessKey2LastUsedDate:    aws.Time(time.Time{}),
			AccessKey2LastUsedRegion:  aws.String("N/A"),
			AccessKey2LastUsedService: aws.String("N/A"),
			Cert1Active:               aws.Bool(false),
			Cert1LastRotated:          aws.Time(time.Time{}),
			Cert2Active:               aws.Bool(false),
			Cert2LastRotated:          aws.Time(time.Time{}),
		},
		"Franklin": {
			UserName:                  aws.String("Franklin"),
			ARN:                       aws.String("arn:aws:iam::123456789012:user/Franklin"),
			UserCreationTime:          aws.Time(utils.ParseTimeRFC3339("2019-04-01T23:51:37+00:00")),
			PasswordEnabled:           aws.Bool(false),
			PasswordLastUsed:          aws.Time(utils.ParseTimeRFC3339("2019-04-02T17:16:30+00:00")),
			PasswordLastChanged:       aws.Time(time.Time{}),
			PasswordNextRotation:      aws.Time(time.Time{}),
			MfaActive:                 aws.Bool(false),
			AccessKey1Active:          aws.Bool(false),
			AccessKey1LastRotated:     aws.Time(time.Time{}),
			AccessKey1LastUsedDate:    aws.Time(time.Time{}),
			AccessKey1LastUsedRegion:  aws.String("N/A"),
			AccessKey1LastUsedService: aws.String("N/A"),
			AccessKey2Active:          aws.Bool(false),
			AccessKey2LastRotated:     aws.Time(time.Time{}),
			AccessKey2LastUsedDate:    aws.Time(time.Time{}),
			AccessKey2LastUsedRegion:  aws.String("N/A"),
			AccessKey2LastUsedService: aws.String("N/A"),
			Cert1Active:               aws.Bool(false),
			Cert1LastRotated:          aws.Time(time.Time{}),
			Cert2Active:               aws.Bool(false),
			Cert2LastRotated:          aws.Time(time.Time{}),
		},
		"unit_test_user": {
			UserName:                  aws.String("unit_test_user"),
			ARN:                       aws.String("arn:aws:iam::123456789012:user/unit_test_user"),
			UserCreationTime:          aws.Time(utils.ParseTimeRFC3339("2018-12-18T23:44:51+00:00")),
			PasswordEnabled:           aws.Bool(true),
			PasswordLastUsed:          aws.Time(utils.ParseTimeRFC3339("2019-05-30T15:40:58+00:00")),
			PasswordLastChanged:       aws.Time(utils.ParseTimeRFC3339("2019-04-03T15:16:13+00:00")),
			PasswordNextRotation:      aws.Time(utils.ParseTimeRFC3339("2019-07-02T15:16:13+00:00")),
			MfaActive:                 aws.Bool(true),
			AccessKey1Active:          aws.Bool(true),
			AccessKey1LastRotated:     aws.Time(utils.ParseTimeRFC3339("2019-05-29T23:36:39+00:00")),
			AccessKey1LastUsedDate:    aws.Time(utils.ParseTimeRFC3339("2019-05-30T20:14:00+00:00")),
			AccessKey1LastUsedRegion:  aws.String("us-east-1"),
			AccessKey1LastUsedService: aws.String("sts"),
			AccessKey2Active:          aws.Bool(false),
			AccessKey2LastRotated:     aws.Time(utils.ParseTimeRFC3339("2019-04-02T20:45:11+00:00")),
			AccessKey2LastUsedDate:    aws.Time(utils.ParseTimeRFC3339("2019-05-29T20:33:00+00:00")),
			AccessKey2LastUsedRegion:  aws.String("us-east-1"),
			AccessKey2LastUsedService: aws.String("sts"),
			Cert1Active:               aws.Bool(false),
			Cert1LastRotated:          aws.Time(time.Time{}),
			Cert2Active:               aws.Bool(false),
			Cert2LastRotated:          aws.Time(time.Time{}),
		},
	}

	ExampleGenerateCredentialReport = &iam.GenerateCredentialReportOutput{
		Description: aws.String("Ok alright"),
		State:       aws.String("COMPLETE"),
	}

	ExampleGenerateCredentialReportProg = &iam.GenerateCredentialReportOutput{
		Description: aws.String("Not ok Not alright"),
		State:       aws.String("INPROGRESS"),
	}

	GenerateCredentialReportInProgress = false

	//
	// Example IAM Users, MFA Devices, Groups, and Policies
	//

	ExampleListUsers = &iam.ListUsersOutput{
		IsTruncated: aws.Bool(false),
		Users: []*iam.User{
			{
				Arn:        aws.String("arn:aws:iam::123456789012:user/unit_test_user"),
				CreateDate: ExampleDate,
				Path:       aws.String("/service_accounts/"),
				UserId:     aws.String("AAAAAAAQQQQQO2HVVVVVV"),
				UserName:   aws.String("unit_test_user"),
			},
			{
				Arn:        aws.String("arn:aws:iam::123456789012:user/Franklin"),
				CreateDate: ExampleDate,
				Path:       aws.String("/"),
				UserId:     aws.String("AIDA4PIQ2YYOO2HYP2JNV"),
				UserName:   aws.String("Franklin"),
			},
		},
	}

	ExampleGetUsers = map[string]*iam.GetUserOutput{
		*ExampleListUsers.Users[0].UserName: {User: ExampleListUsers.Users[0]},
		*ExampleListUsers.Users[1].UserName: {User: ExampleListUsers.Users[1]},
	}

	ExampleListGroupsForUserOutput = &iam.ListGroupsForUserOutput{
		Groups: []*iam.Group{
			ExampleGroup,
		},
	}

	ExampleGetUserPolicy = &iam.GetUserPolicyOutput{
		UserName:       aws.String("Franklin"),
		PolicyName:     aws.String("KinesisWriteOnly"),
		PolicyDocument: aws.String("JSON POLICY DOCUMENT"),
	}

	ExampleListVirtualMFADevices = &iam.ListVirtualMFADevicesOutput{
		IsTruncated: aws.Bool(false),
		VirtualMFADevices: []*iam.VirtualMFADevice{
			{
				SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/root-account-mfa-device"),
				EnableDate:   ExampleDate,
				User: &iam.User{
					Arn:        aws.String("arn:aws:iam::123456789012:root"),
					CreateDate: ExampleDate,
					Path:       aws.String("/"),
					UserId:     aws.String("123456789012"),
					UserName:   aws.String(""),
				},
			},
			{
				SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/unit_test_user"),
				EnableDate:   ExampleDate,
				User: &iam.User{
					Arn:        aws.String("arn:aws:iam::123456789012:user/unit_test_user"),
					CreateDate: ExampleDate,
					Path:       aws.String("/service_accounts/"),
					UserId:     aws.String("AAAAAAAQQQQQO2HVVVVVV"),
					UserName:   aws.String("service_accounts"),
				},
			},
		},
	}

	ExampleListUserPolicies = &iam.ListUserPoliciesOutput{
		PolicyNames: []*string{
			aws.String("KinesisWriteOnly"),
			aws.String("SQSCreateQueue"),
		},
	}

	ExampleListAttachedUserPolicies = &iam.ListAttachedUserPoliciesOutput{
		AttachedPolicies: []*iam.AttachedPolicy{
			{
				PolicyName: aws.String("ForceMFA"),
			},
			{
				PolicyName: aws.String("IAMAdministrator"),
			},
		},
	}

	ExampleGroup = &iam.Group{
		CreateDate: &ExampleTimeParsed,
		GroupId:    aws.String("1234"),
		GroupName:  aws.String("example-group"),
		Path:       aws.String("/"),
		Arn:        aws.String("arn:aws:iam::123456789012:group/example-group"),
	}

	ExampleListGroupsOutput = &iam.ListGroupsOutput{
		Groups: []*iam.Group{
			ExampleGroup,
		},
	}

	ExampleGetGroupOutput = &iam.GetGroupOutput{
		Group: ExampleGroup,
		Users: []*iam.User{
			{
				UserName: aws.String("Bob"),
				UserId:   aws.String("111222333444"),
			},
		},
	}

	ExampleListGroupPolicies = &iam.ListGroupPoliciesOutput{
		PolicyNames: []*string{
			aws.String("GroupPolicy1"),
			aws.String("GroupPolicy2"),
		},
	}

	ExampleGetGroupPolicy = &iam.GetGroupPolicyOutput{
		GroupName:      aws.String("TestGroup"),
		PolicyName:     aws.String("TestPolicyName"),
		PolicyDocument: aws.String("JSON POLICY DOCUMENT"),
	}

	ExampleListAttachedGroupPolicies = &iam.ListAttachedGroupPoliciesOutput{
		AttachedPolicies: []*iam.AttachedPolicy{
			{
				PolicyName: aws.String("AttachedGroupPolicy1"),
				PolicyArn:  aws.String("arn:aws:iam::123456789012:group/example-group/policy"),
			},
		},
	}

	//
	// Example Policy data
	//

	ExampleListPolicies = &iam.ListPoliciesOutput{
		Policies: []*iam.Policy{
			{
				Arn:                           aws.String("arn:aws:iam::aws:policy/aws-service-role/AWSSupportServiceRolePolicy"),
				AttachmentCount:               aws.Int64(1),
				CreateDate:                    ExampleDate,
				DefaultVersionId:              aws.String("v4"),
				IsAttachable:                  aws.Bool(false),
				Path:                          aws.String("/aws-service-role/"),
				PermissionsBoundaryUsageCount: aws.Int64(0),
				PolicyId:                      aws.String("ANPAJ7W6266ELXF5MISDS"),
				PolicyName:                    aws.String("AWSSupportServiceRolePolicy"),
				UpdateDate:                    ExampleDate,
			},
		},
	}

	ExamplePolicyDocumentEncoded = aws.String(url.QueryEscape(
		`{”PolicyVersion”: {”Document”: {”Version”: ”2012-10-17”,”Statement”: [{”Action"": [”appstream:Get*”,”appstream:List*”,“appstream:Describe*”],“Effect”: ”Allow”,”Resource”: ”*”}]},”VersionId”: ”v2”,”IsDefaultVersion”: true,“CreateDate”: ”2016-12-07T21:00:06Z”}}`))
	ExamplePolicyDocumentDecoded = aws.String(
		`{”PolicyVersion”: {”Document”: {”Version”: ”2012-10-17”,”Statement”: [{”Action"": [”appstream:Get*”,”appstream:List*”,“appstream:Describe*”],“Effect”: ”Allow”,”Resource”: ”*”}]},”VersionId”: ”v2”,”IsDefaultVersion”: true,“CreateDate”: ”2016-12-07T21:00:06Z”}}`)

	ExamplePolicyVersionOutput = &iam.GetPolicyVersionOutput{
		PolicyVersion: &iam.PolicyVersion{
			Document:         ExamplePolicyDocumentEncoded,
			IsDefaultVersion: aws.Bool(true),
			VersionId:        aws.String("v2"),
		},
	}

	ExampleListEntitiesForPolicy = &iam.ListEntitiesForPolicyOutput{
		PolicyRoles: []*iam.PolicyRole{
			{
				RoleId:   aws.String("AROA4PIQ2YYOH6ORE5WWX"),
				RoleName: aws.String("AWSServiceRoleForSupport"),
			},
		},
		PolicyGroups: []*iam.PolicyGroup{},
		PolicyUsers:  []*iam.PolicyUser{},
	}

	//
	// Example IAM Role data
	//

	ExampleRoleID  = aws.String("AAABBB123456BBBAAA")
	ExampleIAMRole = &iam.Role{
		Path:       aws.String("/"),
		RoleName:   aws.String("test-role"),
		RoleId:     ExampleRoleID,
		Arn:        aws.String("arn:aws:iam::123456789012:role/test-role"),
		CreateDate: ExampleDate,
		AssumeRolePolicyDocument: aws.String("" +
			"Version: \"2012-10-17, " +
			"Statement: [" +
			"{" +
			"\"Effect\": \"Allow\"," +
			"\"Principal\": {" +
			"\"AWS\": [\"arn:aws:iam::123456789012:user/Franklin\"," +
			"]" +
			"}," +
			"\"Action\": \"sts:AssumeRole\"" +
			"}" +
			"]",
		),
		Description:        aws.String("This is a test role."),
		MaxSessionDuration: aws.Int64(3600),
	}

	ExampleListRolesOutput = &iam.ListRolesOutput{
		Roles: []*iam.Role{
			ExampleIAMRole,
		},
	}

	ExampleGetRoles = map[string]*iam.GetRoleOutput{
		*ExampleListRolesOutput.Roles[0].RoleName: {Role: ExampleListRolesOutput.Roles[0]},
	}

	ExampleListRolePoliciesOutput = &iam.ListRolePoliciesOutput{
		PolicyNames: []*string{
			aws.String("KinesisWriteOnly"),
			aws.String("SQSCreateQueue"),
		},
	}

	ExampleListAttachedRolePoliciesOutput = &iam.ListAttachedRolePoliciesOutput{
		AttachedPolicies: []*iam.AttachedPolicy{
			{
				PolicyArn:  aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
				PolicyName: aws.String("AdministratorAccess"),
			},
		},
	}

	ExampleGetRolePolicy = &iam.GetRolePolicyOutput{
		RoleName:       aws.String("ExampleRole"),
		PolicyName:     aws.String("PolicyName"),
		PolicyDocument: aws.String("JSON POLICY DOCUMENT"),
	}

	svcIAMSetupCalls = map[string]func(*MockIAM){
		// IAM Group Functions
		"GetGroup": func(svc *MockIAM) {
			svc.On("GetGroup", mock.Anything).
				Return(ExampleGetGroupOutput, nil)
		},
		"ListGroupsPages": func(svc *MockIAM) {
			svc.On("ListGroupsPages", mock.Anything).
				Return(nil)
		},
		"ListGroupPoliciesPages": func(svc *MockIAM) {
			svc.On("ListGroupPoliciesPages", mock.Anything).
				Return(nil)
		},
		"ListAttachedGroupPoliciesPages": func(svc *MockIAM) {
			svc.On("ListAttachedGroupPoliciesPages", mock.Anything).
				Return(nil)
		},
		"GetGroupPolicy": func(svc *MockIAM) {
			svc.On("GetGroupPolicy", mock.Anything).
				Return(ExampleGetGroupPolicy, nil)
		},
		// IAM Password Policy Functions
		"GetAccountPasswordPolicy": func(svc *MockIAM) {
			svc.On("GetAccountPasswordPolicy", mock.Anything).
				Return(ExamplePasswordPolicyOutput, nil)
		},
		// IAM Policy Functions
		"GetPolicyVersion": func(svc *MockIAM) {
			svc.On("GetPolicyVersion", mock.Anything).
				Return(ExamplePolicyVersionOutput, nil)
		},
		"ListEntitiesForPolicyPages": func(svc *MockIAM) {
			svc.On("ListEntitiesForPolicyPages", mock.Anything).
				Return(nil)
		},
		"ListPoliciesPages": func(svc *MockIAM) {
			svc.On("ListPoliciesPages", mock.Anything).
				Return(nil)
		},
		// IAM Role Functions
		"ListAttachedRolePoliciesPages": func(svc *MockIAM) {
			svc.On("ListAttachedRolePoliciesPages", mock.Anything).
				Return(nil)
		},
		"ListRolesPages": func(svc *MockIAM) {
			svc.On("ListRolesPages", mock.Anything).
				Return(nil)
		},
		"ListRolePoliciesPages": func(svc *MockIAM) {
			svc.On("ListRolePoliciesPages", mock.Anything).
				Return(nil)
		},
		"GetRolePolicy": func(svc *MockIAM) {
			svc.On("GetRolePolicy", mock.Anything).
				Return(ExampleGetRolePolicy, nil)
		},
		"GetRole": func(svc *MockIAM) {
			svc.On("GetRole", mock.Anything).
				Return(nil, nil)
		},
		// IAM User Functions
		"GenerateCredentialReport": func(svc *MockIAM) {
			svc.On("GenerateCredentialReport", mock.Anything).
				Return(ExampleGenerateCredentialReport, nil)
		},
		"GetCredentialReport": func(svc *MockIAM) {
			svc.On("GetCredentialReport", mock.Anything).
				Return(ExampleCredentialReport, nil)
		},
		"ListAttachedUserPoliciesPages": func(svc *MockIAM) {
			svc.On("ListAttachedUserPoliciesPages", mock.Anything).
				Return(nil)
		},
		"ListGroupsForUserPages": func(svc *MockIAM) {
			svc.On("ListGroupsForUserPages", mock.Anything).
				Return(nil)
		},
		"ListUsersPages": func(svc *MockIAM) {
			svc.On("ListUsersPages", mock.Anything).
				Return(nil)
		},
		"ListUserPoliciesPages": func(svc *MockIAM) {
			svc.On("ListUserPoliciesPages", mock.Anything).
				Return(nil)
		},
		"ListVirtualMFADevicesPages": func(svc *MockIAM) {
			svc.On("ListVirtualMFADevicesPages", mock.Anything).
				Return(nil)
		},
		"GetUserPolicy": func(svc *MockIAM) {
			svc.On("GetUserPolicy", mock.Anything).
				Return(ExampleGetUserPolicy, nil)
		},
		"GetUser": func(svc *MockIAM) {
			svc.On("GetUser", mock.Anything).
				Return(nil, nil)
		},
	}

	svcIAMSetupCallsError = map[string]func(*MockIAM){
		// IAM Group Functions
		"GetGroup": func(svc *MockIAM) {
			svc.On("GetGroup", mock.Anything).
				Return(&iam.GetGroupOutput{},
					errors.New("IAM.GetGroup error"))
		},
		"ListGroupsPages": func(svc *MockIAM) {
			svc.On("ListGroupsPages", mock.Anything).
				Return(errors.New("IAM.ListGroupsPages error"))
		},
		"ListGroupPoliciesPages": func(svc *MockIAM) {
			svc.On("ListGroupPoliciesPages", mock.Anything).
				Return(errors.New("IAM.ListGroupPolicies error"))
		},
		"ListAttachedGroupPoliciesPages": func(svc *MockIAM) {
			svc.On("ListAttachedGroupPoliciesPages", mock.Anything).
				Return(errors.New("IAM.ListAttachedGroupPoliciesPages error"))
		},
		"GetGroupPolicy": func(svc *MockIAM) {
			svc.On("GetGroupPolicy", mock.Anything).
				Return(&iam.GetGroupPolicyOutput{},
					errors.New("IAM.GetGroupPolicy error"))
		},
		// IAM Password Policy Functions
		"GetAccountPasswordPolicy": func(svc *MockIAM) {
			svc.On("GetAccountPasswordPolicy", mock.Anything).
				Return(&iam.GetAccountPasswordPolicyOutput{},
					errors.New("IAM.GetAccountPasswordPolicy error"))
		},
		// IAM Policy Functions
		"GetPolicyVersion": func(svc *MockIAM) {
			svc.On("GetPolicyVersion", mock.Anything).
				Return(&iam.GetPolicyVersionOutput{},
					errors.New("IAM.GetPolicyVersion error"),
				)
		},
		"ListEntitiesForPolicyPages": func(svc *MockIAM) {
			svc.On("ListEntitiesForPolicyPages", mock.Anything).
				Return(errors.New("IAM.ListEntitiesForPolicyPages error"))
		},
		"ListPoliciesPages": func(svc *MockIAM) {
			svc.On("ListPoliciesPages", mock.Anything).
				Return(errors.New("IAM.ListPoliciesPages error"))
		},
		// IAM Role Functions
		"ListAttachedRolePoliciesPages": func(svc *MockIAM) {
			svc.On("ListAttachedRolePoliciesPages", mock.Anything).
				Return(errors.New("IAM.ListAttachedRolePoliciesPages error"))
		},
		"ListRolesPages": func(svc *MockIAM) {
			svc.On("ListRolesPages", mock.Anything).
				Return(errors.New("IAM.ListRolesPages error"))
		},
		"ListRolePoliciesPages": func(svc *MockIAM) {
			svc.On("ListRolePoliciesPages", mock.Anything).
				Return(errors.New("IAM.ListRolePoliciesPages error"))
		},
		"GetRolePolicy": func(svc *MockIAM) {
			svc.On("GetRolePolicy", mock.Anything).
				Return(&iam.GetRolePolicyOutput{},
					errors.New("IAM.GetRolePolicy error"))
		},
		"GetRole": func(svc *MockIAM) {
			svc.On("GetRole", mock.Anything).
				Return(&iam.GetRoleOutput{},
					errors.New("IAM.GetRole error"))
		},
		// IAM User Functions
		"GenerateCredentialReport": func(svc *MockIAM) {
			svc.On("GenerateCredentialReport", mock.Anything).
				Return(&iam.GenerateCredentialReportOutput{},
					errors.New("fake IAM.GenerateCredentialReport error"),
				)
		},
		"GetCredentialReport": func(svc *MockIAM) {
			svc.On("GetCredentialReport", mock.Anything).
				Return(&iam.GetCredentialReportOutput{},
					errors.New("fake IAM.GetCredentialReport error"),
				)
		},
		"ListAttachedUserPoliciesPages": func(svc *MockIAM) {
			svc.On("ListAttachedUserPoliciesPages", mock.Anything).
				Return(errors.New("fake IAM.ListAttachedUserPolicies error"))
		},
		"ListGroupsForUsersPages": func(svc *MockIAM) {
			svc.On("ListGroupsForUsersPages", mock.Anything).
				Return(errors.New("fake IAM.ListGroupsForUsersPages error"))
		},
		"ListUsersPages": func(svc *MockIAM) {
			svc.On("ListUsersPages", mock.Anything).
				Return(errors.New("fake IAM.ListUsersPages error"))
		},
		"ListUserPoliciesPages": func(svc *MockIAM) {
			svc.On("ListUserPoliciesPages", mock.Anything).
				Return(errors.New("fake IAM.ListUserPolicies error"))
		},
		"ListVirtualMFADevicesPages": func(svc *MockIAM) {
			svc.On("ListVirtualMFADevicesPages", mock.Anything).
				Return(errors.New("fake IAM.ListVirtMFADevices error"))
		},
		"GetUserPolicy": func(svc *MockIAM) {
			svc.On("GetUserPolicy", mock.Anything).
				Return(&iam.GetUserPolicyOutput{},
					errors.New("IAM.GetUserPolicy error"),
				)
		},
		"GetUser": func(svc *MockIAM) {
			svc.On("GetUser", mock.Anything).
				Return(&iam.GetUserOutput{},
					errors.New("IAM.GetUser error"),
				)
		},
	}

	MockIAMForSetup = &MockIAM{}
)

// IAM mock

// SetupMockIAM is used to override the IAM Client initializer.
func SetupMockIAM(sess *session.Session, cfg *aws.Config) interface{} {
	return MockIAMForSetup
}

// MockIAM is a mock IAM client.
type MockIAM struct {
	iamiface.IAMAPI
	mock.Mock
}

// BuildMockIAMSvc builds and returns a MockIAM struct
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockIAMSvc(funcs []string) (mockSvc *MockIAM) {
	mockSvc = &MockIAM{}
	for _, f := range funcs {
		svcIAMSetupCalls[f](mockSvc)
	}
	return
}

// BuildMockIAMSvcError builds and returns a MockIAM struct with errors set
//
// Additionally, the appropriate calls to On and Return are made based on the strings passed in
func BuildMockIAMSvcError(funcs []string) (mockSvc *MockIAM) {
	mockSvc = &MockIAM{}
	for _, f := range funcs {
		svcIAMSetupCallsError[f](mockSvc)
	}
	return
}

// BuildIamServiceSvcAll builds and returns a MockIAM struct
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockIAMSvcAll() (mockSvc *MockIAM) {
	mockSvc = &MockIAM{}
	for _, f := range svcIAMSetupCalls {
		f(mockSvc)
	}
	return
}

// BuildMockIAMSvcAllError builds and returns a MockIAM struct with errors set
//
// Additionally, the appropriate calls to On and Return are made for all possible function calls
func BuildMockIAMSvcAllError() (mockSvc *MockIAM) {
	mockSvc = &MockIAM{}
	for _, f := range svcIAMSetupCallsError {
		f(mockSvc)
	}
	return
}

// ListPolicies is a mock function to return fake list policy data
func (m *MockIAM) ListPolicies(in *iam.ListPoliciesInput) (*iam.ListPoliciesOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.ListPoliciesOutput), args.Error(1)
}

// GetAccountPasswordPolicy is a mock function to return fake password policy data.
func (m *MockIAM) GetAccountPasswordPolicy(in *iam.GetAccountPasswordPolicyInput) (*iam.GetAccountPasswordPolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.GetAccountPasswordPolicyOutput), args.Error(1)
}

// ListUsers is a mock function to return fake list user data
func (m *MockIAM) ListUsers(in *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.ListUsersOutput), args.Error(1)
}

// ListUserPolicies is a mock function to return fake list user policies data
func (m *MockIAM) ListUserPolicies(in *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.ListUserPoliciesOutput), args.Error(1)
}

// ListAttachedUserPolicies is a mock function to return fake list attached user policies data
func (m *MockIAM) ListAttachedUserPolicies(in *iam.ListAttachedUserPoliciesInput) (*iam.ListAttachedUserPoliciesOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.ListAttachedUserPoliciesOutput), args.Error(1)
}

// ListVirtualMFADevicesPages is a mock function to return a fake list of virtual MFA Devices with paging.
func (m *MockIAM) ListVirtualMFADevicesPages(
	in *iam.ListVirtualMFADevicesInput,
	paginationFunction func(*iam.ListVirtualMFADevicesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListVirtualMFADevices, true)
	return args.Error(0)
}

// ListUsersPages is a mock function to return fake list user data with paging.
func (m *MockIAM) ListUsersPages(
	in *iam.ListUsersInput,
	paginationFunction func(*iam.ListUsersOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListUsers, true)
	return args.Error(0)
}

// ListUserPoliciesPages is a mock function to return fake list user policies data with paging
func (m *MockIAM) ListUserPoliciesPages(
	in *iam.ListUserPoliciesInput,
	paginationFunction func(*iam.ListUserPoliciesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListUserPolicies, true)
	return args.Error(0)
}

// ListAttachedUserPoliciesPages is a mock function to return fake list attached user policies data with paging
func (m *MockIAM) ListAttachedUserPoliciesPages(
	in *iam.ListAttachedUserPoliciesInput,
	paginationFunction func(*iam.ListAttachedUserPoliciesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListAttachedUserPolicies, true)
	return args.Error(0)
}

// ListEntitiesForPolicyPages is a mock function to return fake list attached policy entites data with paging
func (m *MockIAM) ListEntitiesForPolicyPages(
	in *iam.ListEntitiesForPolicyInput,
	paginationFunction func(*iam.ListEntitiesForPolicyOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListEntitiesForPolicy, true)
	return args.Error(0)
}

// ListPoliciesPages is a mock function to return fake policies with paging
func (m *MockIAM) ListPoliciesPages(
	in *iam.ListPoliciesInput,
	paginationFunction func(*iam.ListPoliciesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListPolicies, true)
	return args.Error(0)
}

// ListVirtualMFADevices is a mock function to return a fake list of virtual MFA Devices
func (m *MockIAM) ListVirtualMFADevices(in *iam.ListVirtualMFADevicesInput) (*iam.ListVirtualMFADevicesOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.ListVirtualMFADevicesOutput), args.Error(1)
}

// GetCredentialReport is a mock function to return fake credential report data.
func (m *MockIAM) GetCredentialReport(in *iam.GetCredentialReportInput) (*iam.GetCredentialReportOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.GetCredentialReportOutput), args.Error(1)
}

// GenerateCredentialReport is a mock function to return fake generate credential report data. If the credential report is 'not ready', it makes it ready for the next return
func (m *MockIAM) GenerateCredentialReport(in *iam.GenerateCredentialReportInput) (*iam.GenerateCredentialReportOutput, error) {
	if GenerateCredentialReportInProgress {
		GenerateCredentialReportInProgress = false
		return ExampleGenerateCredentialReportProg, nil
	}

	args := m.Called(in)
	return args.Get(0).(*iam.GenerateCredentialReportOutput), args.Error(1)
}

// ListEntitiesForPolicy is a mock function to return fake list entity data
func (m *MockIAM) ListEntitiesForPolicy(in *iam.ListEntitiesForPolicyInput) (*iam.ListEntitiesForPolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.ListEntitiesForPolicyOutput), args.Error(1)
}

// GetPolicyVersion is a mock function to return a fake policy document
func (m *MockIAM) GetPolicyVersion(in *iam.GetPolicyVersionInput) (*iam.GetPolicyVersionOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.GetPolicyVersionOutput), args.Error(1)
}

// ListGroups is a mock function to return fake groups
func (m *MockIAM) ListGroups(in *iam.ListGroupsInput) (*iam.ListGroupsOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.ListGroupsOutput), args.Error(1)
}

func (m *MockIAM) ListGroupsPages(
	in *iam.ListGroupsInput,
	paginationFunction func(*iam.ListGroupsOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListGroupsOutput, true)
	return args.Error(0)
}

func (m *MockIAM) ListGroupPoliciesPages(
	in *iam.ListGroupPoliciesInput,
	paginationFunction func(*iam.ListGroupPoliciesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListGroupPolicies, true)
	return args.Error(0)
}

func (m *MockIAM) ListAttachedGroupPoliciesPages(
	in *iam.ListAttachedGroupPoliciesInput,
	paginationFunction func(*iam.ListAttachedGroupPoliciesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListAttachedGroupPolicies, true)
	return args.Error(0)
}

// GetGroup is a mock function to return a fake IAM group
func (m *MockIAM) GetGroup(in *iam.GetGroupInput) (*iam.GetGroupOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.GetGroupOutput), args.Error(1)
}

// GetGroup is a mock function to return a fake IAM group policy
func (m *MockIAM) GetGroupPolicy(in *iam.GetGroupPolicyInput) (*iam.GetGroupPolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.GetGroupPolicyOutput), args.Error(1)
}

func (m *MockIAM) ListRolesPages(
	in *iam.ListRolesInput,
	paginationFunction func(*iam.ListRolesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListRolesOutput, true)
	return args.Error(0)
}

func (m *MockIAM) GetRolePolicy(in *iam.GetRolePolicyInput) (*iam.GetRolePolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.GetRolePolicyOutput), args.Error(1)
}

func (m *MockIAM) ListRolePoliciesPages(
	in *iam.ListRolePoliciesInput,
	paginationFunction func(*iam.ListRolePoliciesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListRolePoliciesOutput, true)
	return args.Error(0)
}

func (m *MockIAM) ListAttachedRolePoliciesPages(
	in *iam.ListAttachedRolePoliciesInput,
	paginationFunction func(*iam.ListAttachedRolePoliciesOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListAttachedRolePoliciesOutput, true)
	return args.Error(0)
}

func (m *MockIAM) ListGroupsForUserPages(
	in *iam.ListGroupsForUserInput,
	paginationFunction func(*iam.ListGroupsForUserOutput, bool) bool,
) error {

	args := m.Called(in)
	if args.Error(0) != nil {
		return args.Error(0)
	}
	paginationFunction(ExampleListGroupsForUserOutput, true)
	return args.Error(0)
}

func (m *MockIAM) GetUserPolicy(in *iam.GetUserPolicyInput) (*iam.GetUserPolicyOutput, error) {
	args := m.Called(in)
	return args.Get(0).(*iam.GetUserPolicyOutput), args.Error(1)
}

// For better unit test accuracy, these two cases return different output depending on the input
func (m *MockIAM) GetUser(in *iam.GetUserInput) (*iam.GetUserOutput, error) {
	args := m.Called(in)
	if args.Error(1) == nil {
		return ExampleGetUsers[*in.UserName], args.Error(1)
	}
	return args.Get(0).(*iam.GetUserOutput), args.Error(1)
}

func (m *MockIAM) GetRole(in *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	args := m.Called(in)
	if args.Error(1) == nil {
		return ExampleGetRoles[*in.RoleName], args.Error(1)
	}
	return args.Get(0).(*iam.GetRoleOutput), args.Error(1)
}
