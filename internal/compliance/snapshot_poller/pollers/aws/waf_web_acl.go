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
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/waf"
	"github.com/aws/aws-sdk-go/service/waf/wafiface"
	"github.com/aws/aws-sdk-go/service/wafregional"
	"github.com/aws/aws-sdk-go/service/wafregional/wafregionaliface"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/lambda/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	// Functions to initialize the WAF and WAF Regional client functions
	WafRegionalClientFunc = setupWafRegionalClient
	WafClientFunc         = setupWafClient
)

func setupWafRegionalClient(sess *session.Session, cfg *aws.Config) interface{} {
	return wafregional.New(sess, cfg)
}

func getWafRegionalClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (wafregionaliface.WAFRegionalAPI, error) {
	client, err := getClient(pollerResourceInput, WafRegionalClientFunc, "waf-regional", region)
	if err != nil {
		return nil, err
	}

	return client.(wafregionaliface.WAFRegionalAPI), nil
}

func setupWafClient(sess *session.Session, cfg *aws.Config) interface{} {
	return waf.New(sess, cfg)
}

func getWafClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (wafiface.WAFAPI, error) {
	client, err := getClient(pollerResourceInput, WafClientFunc, "waf", region)
	if err != nil {
		return nil, err
	}

	return client.(wafiface.WAFAPI), nil
}

// PollWAFWebACL polls a single WAF WebACL resource
func PollWAFWebACL(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	_ *pollermodels.ScanEntry,
) (interface{}, error) {

	client, err := getWafClient(pollerResourceInput, defaultRegion)
	if err != nil {
		return nil, err
	}
	webACLID := strings.Replace(resourceARN.Resource, "webacl/", "", 1)

	snapshot, err := buildWafWebACLSnapshot(client, aws.String(webACLID))
	if err != nil || snapshot == nil {
		return nil, err
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(awsmodels.GlobalRegion)
	snapshot.ResourceType = aws.String(awsmodels.WafWebAclSchema)
	return snapshot, nil
}

// PollWAFRegionalWebACL polls a single WAF Regional WebACL resource
func PollWAFRegionalWebACL(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	resourceARN arn.ARN,
	_ *pollermodels.ScanEntry,
) (interface{}, error) {

	client, err := getWafRegionalClient(pollerResourceInput, resourceARN.Region)
	if err != nil {
		return nil, err
	}
	webACLID := strings.Replace(resourceARN.Resource, "webacl/", "", 1)

	snapshot, err := buildWafWebACLSnapshot(client, aws.String(webACLID))
	if err != nil || snapshot == nil {
		return nil, err
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ResourceType = aws.String(awsmodels.WafRegionalWebAclSchema)
	return snapshot, nil
}

// listWebAcls returns a list web ACLs in the account
//
// The AWS go SDK's do not appear to have built in functions to handle pagination for this API call,
// so it is being done here explicitly.
func listWebAcls(wafSvc wafiface.WAFAPI, nextMarker *string) ([]*waf.WebACLSummary, *string, error) {
	var webAclsSummaryOut []*waf.WebACLSummary
	for len(webAclsSummaryOut) < defaultBatchSize {
		webAclsOutput, err := wafSvc.ListWebACLs(&waf.ListWebACLsInput{
			NextMarker: nextMarker,
			Limit:      aws.Int64(int64(defaultBatchSize)),
		})
		if err != nil {
			if _, ok := wafSvc.(wafregionaliface.WAFRegionalAPI); ok {
				return nil, nil, errors.Wrap(err, "WAF.Regional.ListWebAcls")
			}
			return nil, nil, errors.Wrap(err, "WAF.ListWebAcls")
		}

		// There is no explicit indicator that we've reached the last page of results, we just know
		// that when a page returns 0 results that the previous page was the last page
		if len(webAclsOutput.WebACLs) == 0 {
			return webAclsSummaryOut, nil, nil
		}
		webAclsSummaryOut = append(webAclsSummaryOut, webAclsOutput.WebACLs...)
		nextMarker = webAclsOutput.NextMarker
	}

	return webAclsSummaryOut, nextMarker, nil
}

// getWebACL gets detailed information about a given WEB acl
func getWebACL(wafSvc wafiface.WAFAPI, id *string) (*waf.WebACL, error) {
	out, err := wafSvc.GetWebACL(&waf.GetWebACLInput{WebACLId: id})
	if err != nil {
		return nil, errors.Wrapf(err, "WAF.GetWebACL: %s", aws.StringValue(id))
	}

	return out.WebACL, nil
}

// listTagsForResource returns the tags for a give WAF WebACL
func listTagsForResourceWaf(svc wafiface.WAFAPI, arn *string) ([]*waf.Tag, error) {
	tags, err := svc.ListTagsForResource(&waf.ListTagsForResourceInput{ResourceARN: arn})
	if err != nil {
		return nil, errors.Wrapf(err, "WAF.ListTagsForResource: %s", aws.StringValue(arn))
	}
	return tags.TagInfoForResource.TagList, nil
}

// getRule returns the rule body for a given WAF rule id
func getRule(svc wafiface.WAFAPI, ruleID *string) (*waf.Rule, error) {
	rule, err := svc.GetRule(&waf.GetRuleInput{RuleId: ruleID})
	if err != nil {
		return nil, errors.Wrapf(err, "WAF.GetRule: %s", aws.StringValue(ruleID))
	}
	return rule.Rule, nil
}

// buildWafWebACLSnapshot makes all the calls to build up a snapshot of a given web acl
func buildWafWebACLSnapshot(wafSvc wafiface.WAFAPI, webACLID *string) (*awsmodels.WafWebAcl, error) {
	if webACLID == nil {
		return nil, nil
	}

	webACL, err := getWebACL(wafSvc, webACLID)
	if err != nil {
		var awsErr awserr.Error
		if errors.As(err, &awsErr) {
			if awsErr.Code() == "WAFNonexistentItemException" {
				if _, ok := wafSvc.(wafregionaliface.WAFRegionalAPI); ok {
					zap.L().Warn("tried to scan non-existent resource",
						zap.String("resource", *webACLID),
						zap.String("resourceType", awsmodels.WafRegionalWebAclSchema))
					return nil, nil
				}
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resource", *webACLID),
					zap.String("resourceType", awsmodels.WafWebAclSchema))
				return nil, nil
			}
		}
		if _, ok := wafSvc.(wafregionaliface.WAFRegionalAPI); ok {
			return nil, errors.WithMessage(err, "WAF.Regional.GetWebAcl")
		}
		return nil, errors.WithMessage(err, "WAF.GetWebAcl")
	}

	webACLSnapshot := &awsmodels.WafWebAcl{
		GenericResource: awsmodels.GenericResource{
			ResourceID: webACL.WebACLArn,
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			ARN:  webACL.WebACLArn,
			ID:   webACLID,
			Name: webACL.Name,
		},
		DefaultAction: webACL.DefaultAction,
		MetricName:    webACL.MetricName,
	}

	for _, rule := range webACL.Rules {
		ruleBody, err := getRule(wafSvc, rule.RuleId)
		if err != nil {
			return nil, err
		}
		webACLSnapshot.Rules = append(webACLSnapshot.Rules, &awsmodels.WafRule{
			ActivatedRule: rule,
			Rule:          ruleBody,
			RuleId:        rule.RuleId,
		})
	}

	tags, err := listTagsForResourceWaf(wafSvc, webACLSnapshot.ARN)
	if err != nil {
		return nil, err
	}
	webACLSnapshot.Tags = utils.ParseTagSlice(tags)

	return webACLSnapshot, nil
}

func PollWafRegionalWebAcls(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting regional WAF Web Acl resource poller")

	wafRegionalSvc, err := getWafRegionalClient(pollerInput, *pollerInput.Region)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all regional web acls
	regionalWebACLsSummaries, marker, err := listWebAcls(wafRegionalSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: %s", *pollerInput.Region)
	}

	var resources []apimodels.AddResourceEntry
	for _, regionalWebACL := range regionalWebACLsSummaries {
		regionalWebACLSnapshot, err := buildWafWebACLSnapshot(wafRegionalSvc, regionalWebACL.WebACLId)
		if err != nil {
			return nil, nil, err
		}
		if regionalWebACLSnapshot == nil {
			continue
		}
		regionalWebACLSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		regionalWebACLSnapshot.Region = pollerInput.Region
		regionalWebACLSnapshot.ResourceType = aws.String(awsmodels.WafRegionalWebAclSchema)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      regionalWebACLSnapshot,
			ID:              *regionalWebACLSnapshot.ARN,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.WafRegionalWebAclSchema,
		})
	}

	return resources, marker, nil
}

// PollWafWebAcls gathers information on each Web ACL for an AWS account.
func PollWafWebAcls(pollerInput *awsmodels.ResourcePollerInput) ([]apimodels.AddResourceEntry, *string, error) {
	zap.L().Debug("starting global WAF Web Acl resource poller")

	wafSvc, err := getWafClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, nil, err
	}

	// Start with generating a list of all global web acls
	globalWebAclsSummaries, marker, err := listWebAcls(wafSvc, pollerInput.NextPageToken)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "region: global")
	}
	var resources []apimodels.AddResourceEntry
	for _, webACL := range globalWebAclsSummaries {
		webACLSnapshot, err := buildWafWebACLSnapshot(wafSvc, webACL.WebACLId)
		if err != nil {
			return nil, nil, err
		}
		if webACLSnapshot == nil {
			continue
		}
		webACLSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		webACLSnapshot.Region = aws.String(awsmodels.GlobalRegion)
		webACLSnapshot.ResourceType = aws.String(awsmodels.WafWebAclSchema)

		resources = append(resources, apimodels.AddResourceEntry{
			Attributes:      webACLSnapshot,
			ID:              *webACLSnapshot.ARN,
			IntegrationID:   *pollerInput.IntegrationID,
			IntegrationType: integrationType,
			Type:            awsmodels.WafWebAclSchema,
		})
	}

	return resources, marker, nil
}
