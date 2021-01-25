package aws

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
	"encoding/csv"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/cenkalti/backoff/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

const (
	// Time to delay the requeue of a scan of IAM Users when the credential report times out
	credentialReportRequeueDelaySeconds = 90
	maxCredReportBackoff                = 1 * time.Minute
	rootAccountNameCredReport           = "<root_account>"
	rootDeviceSerialSuffix              = ":mfa/root-account-mfa-device"
	throttlingErrorCode                 = "Throttling"
)

var (
	userCredentialReports map[string]*awsmodels.IAMCredentialReport
	mfaDeviceMapping      map[string]*awsmodels.VirtualMFADevice
)

// PollIAMUser polls a single IAM User resource
func PollIAMUser(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	iamClient, err := getIAMClient(pollerResourceInput, defaultRegion)
	if err != nil {
		return nil, err
	}

	// See PollIAMRole for an explanation of this behavior
	resourceSplit := strings.Split(resourceARN.Resource, "/")
	user, err := getUser(iamClient, aws.String(resourceSplit[len(resourceSplit)-1]))
	if err != nil || user == nil {
		return nil, err
	}

	// Refresh the caches as needed
	mfaDeviceMapping, err = listVirtualMFADevices(iamClient)
	if err != nil {
		return nil, err
	}
	userCredentialReports, err = buildCredentialReport(iamClient)
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == throttlingErrorCode {
			// Check if we got rate limited, happens sometimes when the credential report takes a long time to generate
			zap.L().Debug("credential report lookup rate limited during single user scan", zap.String("resourceId", *scanRequest.ResourceID))
			err = utils.Requeue(pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{scanRequest},
			}, credentialReportRequeueDelaySeconds)
			return nil, err
		}
		return nil, err
	}

	snapshot, err := buildIAMUserSnapshot(iamClient, user)
	if err != nil {
		return nil, err
	}

	// If the user does not have a credential report, then continue on with the snapshot but
	// re-queue the user for a scan in fifteen minutes (the maximum delay time). The primary reason
	// a user would not have a credential report is if they were recently created and there has not
	// yet been time for a new credential report that includes them to have been generated.
	if snapshot.CredentialReport == nil {
		err = utils.Requeue(pollermodels.ScanMsg{
			Entries: []*pollermodels.ScanEntry{
				scanRequest,
			},
		}, utils.MaxRequeueDelaySeconds)
		if err != nil {
			return nil, err
		}
	}

	snapshot.AccountID = aws.String(resourceARN.AccountID)
	scanRequest.ResourceID = snapshot.ResourceID
	return snapshot, nil
}

// PollIAMUser polls a single IAM User resource
func PollIAMRootUser(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	_ arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) (interface{}, error) {

	iamClient, err := getIAMClient(pollerResourceInput, defaultRegion)
	if err != nil {
		return nil, err
	}

	// Refresh the caches as needed
	mfaDeviceMapping, err = listVirtualMFADevices(iamClient)
	if err != nil {
		return nil, err
	}
	userCredentialReports, err = buildCredentialReport(iamClient)
	if err != nil {
		return nil, err
	}

	snapshot, err := buildIAMRootUserSnapshot()
	if err != nil {
		return nil, err
	}

	// Over ride this as it may be set incorrectly
	scanRequest.ResourceID = snapshot.ResourceID
	return snapshot, nil
}

// getUser returns an individual IAM user
func getUser(svc iamiface.IAMAPI, userName *string) (*iam.User, error) {
	user, err := svc.GetUser(&iam.GetUserInput{
		UserName: userName,
	})
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == iam.ErrCodeNoSuchEntityException {
			zap.L().Warn("tried to scan non-existent resource",
				zap.String("resource", *userName),
				zap.String("resourceType", awsmodels.IAMUserSchema))
			return nil, nil
		}
		return nil, errors.Wrapf(err, "IAM.GetUser: %s", aws.StringValue(userName))
	}
	return user.User, nil
}

// getCredentialReport retrieves an existing credential report from AWS
func getCredentialReport(svc iamiface.IAMAPI) (*iam.GetCredentialReportOutput, error) {
	var getIn = &iam.GetCredentialReportInput{}
	var getOut *iam.GetCredentialReportOutput
	var getErr error

	if getOut, getErr = svc.GetCredentialReport(getIn); getErr != nil {
		return nil, getErr
	}

	return getOut, nil
}

// generateCredentialReport generates a credential report if one does not exist,
// and does not return until the report has been successfully generated.
func generateCredentialReport(svc iamiface.IAMAPI) (*iam.GenerateCredentialReportOutput, error) {
	var genIn = &iam.GenerateCredentialReportInput{}
	var genOut *iam.GenerateCredentialReportOutput
	var genErr error

	backoffOperation := func() error {
		if genOut, genErr = svc.GenerateCredentialReport(genIn); genErr != nil {
			return backoff.Permanent(genErr)
		}
		if *genOut.State != "COMPLETE" {
			return errors.New("report in progress")
		}
		return nil
	}

	expBackoff := backoff.NewExponentialBackOff()
	expBackoff.MaxElapsedTime = maxCredReportBackoff
	backoffErr := backoff.Retry(backoffOperation, expBackoff)
	if backoffErr != nil {
		return nil, backoffErr
	}

	return genOut, nil
}

func parseCredReportBool(field string) bool {
	convertedBool, err := strconv.ParseBool(field)
	if err != nil {
		return false
	}

	return convertedBool
}

// extractCredentialReport converts a CSV credential report into a mapping of user to parsed report.
func extractCredentialReport(content []byte) (map[string]*awsmodels.IAMCredentialReport, error) {
	csvReader := csv.NewReader(bytes.NewReader(content))
	userCredReportMapping := make(map[string]*awsmodels.IAMCredentialReport)

	credReportRows, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}

	// Iterate through all cred report rows, and skip the header row
	for _, credReportRow := range credReportRows[1:] {
		if len(credReportRow) != 22 {
			zap.L().Error("invalid credential report row")
			continue
		}

		credReport := &awsmodels.IAMCredentialReport{
			UserName:                  aws.String(credReportRow[0]),
			ARN:                       aws.String(credReportRow[1]),
			UserCreationTime:          aws.Time(utils.ParseTimeRFC3339(credReportRow[2])),
			PasswordEnabled:           aws.Bool(parseCredReportBool(credReportRow[3])),
			PasswordLastUsed:          aws.Time(utils.ParseTimeRFC3339(credReportRow[4])),
			PasswordLastChanged:       aws.Time(utils.ParseTimeRFC3339(credReportRow[5])),
			PasswordNextRotation:      aws.Time(utils.ParseTimeRFC3339(credReportRow[6])),
			MfaActive:                 aws.Bool(parseCredReportBool(credReportRow[7])),
			AccessKey1Active:          aws.Bool(parseCredReportBool(credReportRow[8])),
			AccessKey1LastRotated:     aws.Time(utils.ParseTimeRFC3339(credReportRow[9])),
			AccessKey1LastUsedDate:    aws.Time(utils.ParseTimeRFC3339(credReportRow[10])),
			AccessKey1LastUsedRegion:  aws.String(credReportRow[11]),
			AccessKey1LastUsedService: aws.String(credReportRow[12]),
			AccessKey2Active:          aws.Bool(parseCredReportBool(credReportRow[13])),
			AccessKey2LastRotated:     aws.Time(utils.ParseTimeRFC3339(credReportRow[14])),
			AccessKey2LastUsedDate:    aws.Time(utils.ParseTimeRFC3339(credReportRow[15])),
			AccessKey2LastUsedRegion:  aws.String(credReportRow[16]),
			AccessKey2LastUsedService: aws.String(credReportRow[17]),
			Cert1Active:               aws.Bool(parseCredReportBool(credReportRow[18])),
			Cert1LastRotated:          aws.Time(utils.ParseTimeRFC3339(credReportRow[19])),
			Cert2Active:               aws.Bool(parseCredReportBool(credReportRow[20])),
			Cert2LastRotated:          aws.Time(utils.ParseTimeRFC3339(credReportRow[21])),
		}
		userCredReportMapping[credReportRow[0]] = credReport
	}

	return userCredReportMapping, nil
}

// buildCredentialReport obtains an IAM Credential Report and generates a mapping from user to report.
func buildCredentialReport(
	iamSvc iamiface.IAMAPI) (map[string]*awsmodels.IAMCredentialReport, error) {

	var credentialReportRaw *iam.GetCredentialReportOutput
	var err error

	// Try to get the credential report
	credentialReportRaw, err = getCredentialReport(iamSvc)
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) {
			switch awsErr.Code() {
			case iam.ErrCodeCredentialReportNotPresentException, iam.ErrCodeCredentialReportExpiredException:
				zap.L().Debug("no credential report found, generating a new one")
				if _, err := generateCredentialReport(iamSvc); err != nil {
					return nil, err
				}
				credentialReportRaw, err = getCredentialReport(iamSvc)
				if err != nil {
					return nil, err
				}
				return extractCredentialReport(credentialReportRaw.Content)
			}
		}
		return nil, err
	}

	return extractCredentialReport(credentialReportRaw.Content)
}

// listUsers returns all the users in the account, excluding the root account.
func listUsers(iamSvc iamiface.IAMAPI, nextMarker *string) (users []*iam.User, marker *string, err error) {
	err = iamSvc.ListUsersPages(
		&iam.ListUsersInput{
			Marker:   nextMarker,
			MaxItems: aws.Int64(int64(defaultBatchSize)),
		},
		func(page *iam.ListUsersOutput, lastPage bool) bool {
			return iamUserIterator(page, &users, &marker)
		},
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "IAM.ListUsersPages")
	}
	return
}

func iamUserIterator(page *iam.ListUsersOutput, users *[]*iam.User, marker **string) bool {
	*users = append(*users, page.Users...)
	*marker = page.Marker
	return len(*users) < defaultBatchSize
}

// getUserPolicies aggregates all the policies assigned to a user by polling both
// the ListUserPolicies and ListAttachedUserPolicies APIs.
func getUserPolicies(iamSvc iamiface.IAMAPI, userName *string) (inlinePolicies []*string, managedPolicies []*string, err error) {
	err = iamSvc.ListUserPoliciesPages(
		&iam.ListUserPoliciesInput{UserName: userName},
		func(page *iam.ListUserPoliciesOutput, lastPage bool) bool {
			inlinePolicies = append(inlinePolicies, page.PolicyNames...)
			return true
		},
	)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "IAM.ListUserPolicies: %s", aws.StringValue(userName))
	}

	err = iamSvc.ListAttachedUserPoliciesPages(
		&iam.ListAttachedUserPoliciesInput{UserName: userName},
		func(page *iam.ListAttachedUserPoliciesOutput, lastPage bool) bool {
			for _, attachedPolicy := range page.AttachedPolicies {
				managedPolicies = append(managedPolicies, attachedPolicy.PolicyName)
			}
			return true
		},
	)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "IAM.ListAttachedUserPolicies: %s", aws.StringValue(userName))
	}

	return
}

// listVirtualMFADevices returns a mapping of UserID to VirtualMFADeviceSnapshot.
func listVirtualMFADevices(
	iamSvc iamiface.IAMAPI) (map[string]*awsmodels.VirtualMFADevice, error) {

	vmfaDevicesInput := &iam.ListVirtualMFADevicesInput{
		// We only want MFA devices associated with a user.
		AssignmentStatus: aws.String("Assigned"),
	}
	var vmfaDevices []*iam.VirtualMFADevice
	err := iamSvc.ListVirtualMFADevicesPages(
		vmfaDevicesInput,
		func(page *iam.ListVirtualMFADevicesOutput, lastPage bool) bool {
			vmfaDevices = append(vmfaDevices, page.VirtualMFADevices...)
			return true
		},
	)
	if err != nil {
		return nil, errors.Wrap(err, "IAM.ListVirtualMFADevicesPages")
	}

	mfaDeviceMapping := make(map[string]*awsmodels.VirtualMFADevice)
	for _, vmfaDevice := range vmfaDevices {
		if vmfaDevice.User != nil && vmfaDevice.User.UserId != nil {
			mfaDeviceMapping[*vmfaDevice.User.UserId] = &awsmodels.VirtualMFADevice{
				EnableDate:   vmfaDevice.EnableDate,
				SerialNumber: vmfaDevice.SerialNumber,
			}
		}
	}

	return mfaDeviceMapping, nil
}

// listGroupsForUser returns all the IAM Groups a given IAM User belongs to
func listGroupsForUser(iamSvc iamiface.IAMAPI, userName *string) (groups []*iam.Group, err error) {
	err = iamSvc.ListGroupsForUserPages(&iam.ListGroupsForUserInput{UserName: userName},
		func(page *iam.ListGroupsForUserOutput, lastPage bool) bool {
			groups = append(groups, page.Groups...)
			return true
		})
	if err != nil {
		return nil, errors.Wrapf(err, "IAM.ListGroupsForUserPages: %s", aws.StringValue(userName))
	}
	return
}

// getUserPolicy gets the inline policy documents for a given IAM user and inline policy name
func getUserPolicy(svc iamiface.IAMAPI, userName *string, policyName *string) (*string, error) {
	policy, err := svc.GetUserPolicy(&iam.GetUserPolicyInput{
		UserName:   userName,
		PolicyName: policyName,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "IAM.GetUserPolicy: user %s, policy %s", aws.StringValue(userName), aws.StringValue(policyName))
	}

	decodedPolicy, err := url.QueryUnescape(*policy.PolicyDocument)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"unable to url decode inline policy document of user %s, policy %s",
			aws.StringValue(userName),
			aws.StringValue(policyName),
		)
	}

	return aws.String(decodedPolicy), nil
}

// buildIAMUserSnapshot builds an IAMUserSnapshot for a given IAM User
func buildIAMUserSnapshot(iamSvc iamiface.IAMAPI, user *iam.User) (*awsmodels.IAMUser, error) {
	iamUserSnapshot := &awsmodels.IAMUser{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   user.Arn,
			TimeCreated:  user.CreateDate,
			ResourceType: aws.String(awsmodels.IAMUserSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:    user.Arn,
			ID:     user.UserId,
			Name:   user.UserName,
			Region: aws.String(awsmodels.GlobalRegion),
			Tags:   utils.ParseTagSlice(user.Tags),
		},
		PasswordLastUsed:    user.PasswordLastUsed,
		Path:                user.Path,
		PermissionsBoundary: user.PermissionsBoundary,
	}

	// Get IAM Policies associated to the user.
	inlinePolicyNames, managedPolicies, err := getUserPolicies(iamSvc, user.UserName)
	if err != nil {
		return nil, err
	}
	iamUserSnapshot.ManagedPolicyNames = managedPolicies
	if inlinePolicyNames != nil {
		iamUserSnapshot.InlinePolicies = make(map[string]*string, len(inlinePolicyNames))
		for _, inlinePolicy := range inlinePolicyNames {
			iamUserSnapshot.InlinePolicies[*inlinePolicy], err = getUserPolicy(iamSvc, user.UserName, inlinePolicy)
			if err != nil {
				return nil, err
			}
		}
	}

	if userCredentialReport, ok := userCredentialReports[*user.UserName]; ok {
		iamUserSnapshot.CredentialReport = userCredentialReport
	}

	// Look up any virtual MFA devices attached to the user
	if mfaSnapshot, ok := mfaDeviceMapping[*user.UserId]; ok {
		iamUserSnapshot.VirtualMFA = mfaSnapshot
	}

	// Look up any groups the user is a member of
	iamUserSnapshot.Groups, err = listGroupsForUser(iamSvc, user.UserName)
	if err != nil {
		return nil, err
	}

	return iamUserSnapshot, nil
}

func buildIAMRootUserSnapshot() (*awsmodels.IAMRootUser, error) {
	rootCredReport, ok := userCredentialReports[rootAccountNameCredReport]
	if !ok {
		return nil, errors.New("unable to find credential report for root user")
	}

	rootARN, err := arn.Parse(*rootCredReport.ARN)
	if err != nil {
		return nil, errors.Wrap(err, "unable to extract root user account ID")
	}
	rootSnapshot := &awsmodels.IAMRootUser{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   rootCredReport.ARN,
			TimeCreated:  rootCredReport.UserCreationTime,
			ResourceType: aws.String(awsmodels.IAMRootUserSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			AccountID: aws.String(rootARN.AccountID),
			ARN:       rootCredReport.ARN,
			Name:      rootCredReport.UserName,
			Region:    aws.String(awsmodels.GlobalRegion),
		},
		CredentialReport: rootCredReport,
	}

	// Add final MFA and UserID fields to Root Snapshot
	for userID, vMFADeviceSnapshot := range mfaDeviceMapping {
		if strings.HasSuffix(*vMFADeviceSnapshot.SerialNumber, rootDeviceSerialSuffix) {
			rootSnapshot.ID = aws.String(userID)
			rootSnapshot.VirtualMFA = vMFADeviceSnapshot
		}
	}

	return rootSnapshot, nil
}

// PollIAMUsers generates a snapshot for each IAM User.
func PollIAMUsers(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting IAM User resource poller")
	iamSvc, err := getIAMClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, nil, err
	}

	// List all IAM Users in the account
	users, marker, err := listUsers(iamSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, err
	}

	// Build the credential report for all users
	userCredentialReports, err = buildCredentialReport(iamSvc)
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) && awsErr.Code() == throttlingErrorCode {
			// Check if we got rate limited, which happens sometimes when the credential report takes a long time to generate
			zap.L().Debug(
				"credential report lookup rate limited during all users scan",
				zap.String("accountId", pollerInput.AuthSourceParsedARN.AccountID))
			err = utils.Requeue(pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{{
					AWSAccountID:            aws.String(pollerInput.AuthSourceParsedARN.AccountID),
					IntegrationID:           pollerInput.IntegrationID,
					ResourceType:            aws.String(awsmodels.IAMUserSchema),
					RegionIgnoreList:        pollerInput.RegionIgnoreList,
					ResourceRegexIgnoreList: pollerInput.ResourceRegexIgnoreList,
					ResourceTypeIgnoreList:  pollerInput.ResourceTypeIgnoreList,
				}},
			}, credentialReportRequeueDelaySeconds)
			if err != nil {
				return nil, nil, err
			}
			// Manually re-queueing the re-scan here so we can specify the delay. Don't return
			// an error so that lambda doesn't also try to re-scan.
			return nil, nil, nil
		}
		return nil, nil, err
	}

	// Get all VMFA snapshots
	mfaDeviceMapping, err = listVirtualMFADevices(iamSvc)
	if err != nil {
		return nil, nil, err
	}

	// Create IAM User snapshots
	var resources []apimodels.AddResourceEntry
	for _, user := range users {
		// The IAM.User struct has a Tags field, indicating what tags the User has
		// The API call IAM.GetUser returns an IAM.User struct, with all appropriate fields set
		// The API call IAM.ListUsers returns a slice of IAM.User structs, but does not set the tags
		// field for any of these structs regardless of whether the corresponding user has tags set
		// This patches that gap
		fullUser, err := getUser(iamSvc, user.UserName)
		if err != nil {
			return nil, nil, err
		}
		iamUserSnapshot, err := buildIAMUserSnapshot(iamSvc, fullUser)
		if err != nil {
			return nil, nil, err
		}

		iamUserSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		// If the user does not have a credential report, then continue on with the snapshot but
		// re-queue the user for a scan in fifteen minutes (the maximum delay time). The primary reason
		// a user would not have a credential report is if they were recently created and there has not
		// yet been time for a new credential report that includes them to have been generated.
		if iamUserSnapshot.CredentialReport == nil {
			err = utils.Requeue(pollermodels.ScanMsg{
				Entries: []*pollermodels.ScanEntry{
					{
						AWSAccountID:            iamUserSnapshot.AccountID,
						IntegrationID:           pollerInput.IntegrationID,
						ResourceID:              iamUserSnapshot.ResourceID,
						ResourceType:            iamUserSnapshot.ResourceType,
						RegionIgnoreList:        pollerInput.RegionIgnoreList,
						ResourceRegexIgnoreList: pollerInput.ResourceRegexIgnoreList,
						ResourceTypeIgnoreList:  pollerInput.ResourceTypeIgnoreList,
					},
				},
			}, utils.MaxRequeueDelaySeconds)
			if err != nil {
				return nil, nil, err
			}
		}

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      iamUserSnapshot,
			ID:              *user.Arn,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.IAMUserSchema,
		})
	}

	// We only want to scan the root user once per service scan, so if we're on a subsequent user
	// scan then just skip the root user
	if pollerInput.NextPageToken != nil {
		return resources, marker, nil
	}

	rootSnapshot, err := buildIAMRootUserSnapshot()
	if err != nil {
		return nil, nil, err
	}
	// Create the IAM Root User snapshot
	resources = append(resources, apimodels.AddResourceEntry{
		Attributes:      rootSnapshot,
		ID:              *rootSnapshot.ARN,
		IntegrationID:   *pollerInput.IntegrationID,
		IntegrationType: integrationType,
		Type:            awsmodels.IAMRootUserSchema,
	})

	return resources, marker, nil
}
