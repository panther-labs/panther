package aws

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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/acm/acmiface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	AcmClientFunc = setupAcmClient
)

func setupAcmClient(sess *session.Session, cfg *aws.Config) interface{} {
	cfg.MaxRetries = aws.Int(MaxRetries)
	return acm.New(sess, cfg)
}

// PollACMCertificate a single ACM certificate resource
func PollACMCertificate(
	pollerInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	scanRequest *pollermodels.ScanEntry,
) interface{} {

	client := getClient(pollerInput, "acm", resourceARN.Region).(acmiface.ACMAPI)

	snapshot := buildAcmCertificateSnapshot(client, scanRequest.ResourceID)
	if snapshot == nil {
		return nil
	}
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.AccountID = aws.String(resourceARN.AccountID)

	return snapshot
}

// listCertificates returns all ACM certificates in the account
func listCertificates(acmSvc acmiface.ACMAPI) (certs []*acm.CertificateSummary) {
	err := acmSvc.ListCertificatesPages(&acm.ListCertificatesInput{},
		func(page *acm.ListCertificatesOutput, lastPage bool) bool {
			certs = append(certs, page.CertificateSummaryList...)
			return true
		})
	if err != nil {
		utils.LogAWSError("ACM.ListCertificatesPages", err)
	}
	return
}

// describeCertificates provides detailed information for a given ACM certificate
func describeCertificate(acmSvc acmiface.ACMAPI, arn *string) (*acm.CertificateDetail, error) {
	out, err := acmSvc.DescribeCertificate(&acm.DescribeCertificateInput{CertificateArn: arn})
	if err != nil {
		utils.LogAWSError("ACM.DescribeCertificate", err)
		return nil, err
	}

	return out.Certificate, nil
}

// listTagsForCertificate provides detailed information for a given ACM certificate
func listTagsForCertificate(acmSvc acmiface.ACMAPI, arn *string) ([]*acm.Tag, error) {
	out, err := acmSvc.ListTagsForCertificate(&acm.ListTagsForCertificateInput{CertificateArn: arn})
	if err != nil {
		utils.LogAWSError("ACM.ListTagsForCertificate", err)
		return nil, err
	}

	return out.Tags, nil
}

// buildAcmCertificateSnapshot returns a complete snapshot of an ACM certificate
func buildAcmCertificateSnapshot(acmSvc acmiface.ACMAPI, certificateArn *string) *awsmodels.AcmCertificate {
	if certificateArn == nil {
		return nil
	}

	metadata, err := describeCertificate(acmSvc, certificateArn)
	if err != nil {
		return nil
	}

	acmCertificate := &awsmodels.AcmCertificate{
		GenericResource: awsmodels.GenericResource{
			ResourceID:   certificateArn,
			ResourceType: aws.String(awsmodels.AcmCertificateSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  certificateArn,
			Name: metadata.DomainName,
		},
		CertificateAuthorityArn: metadata.CertificateAuthorityArn,
		DomainName:              metadata.DomainName,
		DomainValidationOptions: metadata.DomainValidationOptions,
		ExtendedKeyUsages:       metadata.ExtendedKeyUsages,
		FailureReason:           metadata.FailureReason,
		InUseBy:                 metadata.InUseBy,
		IssuedAt:                metadata.IssuedAt,
		Issuer:                  metadata.Issuer,
		KeyAlgorithm:            metadata.KeyAlgorithm,
		KeyUsages:               metadata.KeyUsages,
		NotAfter:                metadata.NotAfter,
		NotBefore:               metadata.NotBefore,
		Options:                 metadata.Options,
		RenewalEligibility:      metadata.RenewalEligibility,
		RenewalSummary:          metadata.RenewalSummary,
		RevocationReason:        metadata.RevocationReason,
		RevokedAt:               metadata.RevokedAt,
		Serial:                  metadata.Serial,
		SignatureAlgorithm:      metadata.SignatureAlgorithm,
		Status:                  metadata.Status,
		Subject:                 metadata.Subject,
		SubjectAlternativeNames: metadata.SubjectAlternativeNames,
		Type:                    metadata.Type,
	}

	if *metadata.Type == "AMAZON_CREATED" {
		acmCertificate.TimeCreated = utils.DateTimeFormat(*metadata.CreatedAt)
	} else if *metadata.Type == "IMPORTED" {
		acmCertificate.TimeCreated = utils.DateTimeFormat(*metadata.ImportedAt)
	}

	tags, err := listTagsForCertificate(acmSvc, certificateArn)
	if err != nil {
		return nil
	}
	acmCertificate.Tags = utils.ParseTagSlice(tags)

	return acmCertificate
}

// PollAcmCertificates gathers information on each ACM Certificate for an AWS account.
func PollAcmCertificates(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting ACM Certificate resource poller")
	acmCertificateSnapshots := make(map[string]*awsmodels.AcmCertificate)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "acm") {
		sess := session.Must(session.NewSession(&aws.Config{Region: regionID}))

		creds, err := AssumeRoleFunc(pollerInput, sess)
		if err != nil {
			return nil, err
		}

		acmSvc := AcmClientFunc(sess, &aws.Config{Credentials: creds}).(acmiface.ACMAPI)

		// Start with generating a list of all certificates
		certificates := listCertificates(acmSvc)
		if len(certificates) == 0 {
			zap.L().Debug("no ACM certificates found", zap.String("region", *regionID))
			continue
		}

		for _, certificateSummary := range certificates {
			acmCertificateSnapshot := buildAcmCertificateSnapshot(acmSvc, certificateSummary.CertificateArn)
			if acmCertificateSnapshot == nil {
				continue
			}
			acmCertificateSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			acmCertificateSnapshot.Region = regionID

			if _, ok := acmCertificateSnapshots[*acmCertificateSnapshot.ARN]; !ok {
				acmCertificateSnapshots[*acmCertificateSnapshot.ARN] = acmCertificateSnapshot
			} else {
				zap.L().Info(
					"overwriting existing ACM Certificate snapshot",
					zap.String("resourceId", *acmCertificateSnapshot.ARN),
				)
				acmCertificateSnapshots[*acmCertificateSnapshot.ARN] = acmCertificateSnapshot
			}
		}
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(acmCertificateSnapshots))
	for resourceID, acmSnapshot := range acmCertificateSnapshots {
		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      acmSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.AcmCertificateSchema,
		})
	}

	return resources, nil
}
