package aws

/**
 * A Cloud-Native SIEM for the Modern Security Team
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
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
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
		return nil, err // error is logged in getClient()
	}

	return client.(wafregionaliface.WAFRegionalAPI), nil
}

func setupWafClient(sess *session.Session, cfg *aws.Config) interface{} {
	return waf.New(sess, cfg)
}

func getWafClient(pollerResourceInput *awsmodels.ResourcePollerInput, region string) (wafiface.WAFAPI, error) {
	client, err := getClient(pollerResourceInput, WafClientFunc, "waf", region)
	if err != nil {
		return nil, err // error is logged in getClient()
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

	snapshot := buildWafWebACLSnapshot(client, aws.String(webACLID))
	if snapshot == nil {
		return nil, nil
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

	snapshot := buildWafWebACLSnapshot(client, aws.String(webACLID))
	if snapshot == nil {
		return nil, nil
	}
	snapshot.AccountID = aws.String(resourceARN.AccountID)
	snapshot.Region = aws.String(resourceARN.Region)
	snapshot.ResourceType = aws.String(awsmodels.WafRegionalWebAclSchema)
	return snapshot, nil
}

// listWebAclsRecursive is a helper function for listWebAcls, used to enumerate the web ACLs in an account
func listWebAclsRecursive(wafSvc wafiface.WAFAPI, webAclsSummaryIn []*waf.WebACLSummary, next *string) (
	webAclsSummaryOut []*waf.WebACLSummary) {

	webAclsOutput, err := wafSvc.ListWebACLs(&waf.ListWebACLsInput{NextMarker: next})
	if err != nil {
		if _, ok := wafSvc.(wafregionaliface.WAFRegionalAPI); ok {
			utils.LogAWSError("WAF.Regional.ListWebAcls", err)
		} else {
			utils.LogAWSError("WAF.ListWebAcls", err)
		}
		return
	}

	// base case, there is no way to know if a particular response is the last response without
	// requesting the next response and seeing that you get nothing
	if len(webAclsOutput.WebACLs) == 0 {
		return webAclsSummaryIn
	}
	webAclsSummaryOut = append(webAclsSummaryIn, webAclsOutput.WebACLs...)
	return listWebAclsRecursive(wafSvc, webAclsSummaryOut, webAclsOutput.NextMarker)
}

// listWebAcls returns a list web ACLs in the account
//
// The AWS go SDK's do not appear to have built in functions to handle pagination for this API call,
// so it is being done here explicitly.
func listWebAcls(wafSvc wafiface.WAFAPI) (webAclsSummaryOut []*waf.WebACLSummary) {
	var emptyWebAcls []*waf.WebACLSummary
	return listWebAclsRecursive(wafSvc, emptyWebAcls, nil)
}

// getWebACL gets detailed information about a given WEB acl
func getWebACL(wafSvc wafiface.WAFAPI, id *string) (*waf.WebACL, error) {
	out, err := wafSvc.GetWebACL(&waf.GetWebACLInput{WebACLId: id})
	if err != nil {
		return nil, err
	}

	return out.WebACL, nil
}

// listTagsForResource returns the tags for a give WAF WebACL
func listTagsForResourceWaf(svc wafiface.WAFAPI, arn *string) ([]*waf.Tag, error) {
	tags, err := svc.ListTagsForResource(&waf.ListTagsForResourceInput{ResourceARN: arn})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AccessDeniedException" {
				zap.L().Error(
					"AccessDeniedException, additional permissions were not granted",
					zap.String("API", "WAF.ListTagsForResource"))
				return nil, err
			}
		}
		utils.LogAWSError("WAF.ListTagsForResource", err)
		return nil, err
	}
	return tags.TagInfoForResource.TagList, nil
}

// getRule returns the rule body for a given WAF rule id
func getRule(svc wafiface.WAFAPI, ruleID *string) (*waf.Rule, error) {
	rule, err := svc.GetRule(&waf.GetRuleInput{RuleId: ruleID})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AccessDeniedException" {
				zap.L().Error(
					"AccessDeniedException, additional permissions were not granted",
					zap.String("API", "WAF.GetRule"))
				return nil, err
			}
		}
		utils.LogAWSError("WAF.GetRule", err)
		return nil, err
	}
	return rule.Rule, nil
}

// buildWafWebACLSnapshot makes all the calls to build up a snapshot of a given web acl
func buildWafWebACLSnapshot(wafSvc wafiface.WAFAPI, webACLID *string) *awsmodels.WafWebAcl {
	if webACLID == nil {
		return nil
	}

	webACL, err := getWebACL(wafSvc, webACLID)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "AccessDeniedException" {
				zap.L().Error(
					"AccessDeniedException, additional permissions were not granted",
					zap.String("API", "WAF.GetWebAcl"))
				return nil
			} else if awsErr.Code() == "WAFNonexistentItemException" {
				if _, ok := wafSvc.(wafregionaliface.WAFRegionalAPI); ok {
					zap.L().Warn("tried to scan non-existent resource",
						zap.String("resource", *webACLID),
						zap.String("resourceType", awsmodels.WafRegionalWebAclSchema))
				} else {
					zap.L().Warn("tried to scan non-existent resource",
						zap.String("resource", *webACLID),
						zap.String("resourceType", awsmodels.WafWebAclSchema))
				}
				return nil
			}
		}
		if _, ok := wafSvc.(wafregionaliface.WAFRegionalAPI); ok {
			utils.LogAWSError("WAF.Regional.GetWebAcl", err)
		} else {
			utils.LogAWSError("WAF.GetWebAcl", err)
		}
		return nil
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
		if err == nil {
			webACLSnapshot.Rules = append(webACLSnapshot.Rules, &awsmodels.WafRule{
				ActivatedRule: rule,
				Rule:          ruleBody,
				RuleId:        rule.RuleId,
			})
		}
	}

	tags, err := listTagsForResourceWaf(wafSvc, webACLSnapshot.ARN)
	if err == nil {
		webACLSnapshot.Tags = utils.ParseTagSlice(tags)
	}

	return webACLSnapshot
}

func PollWafRegionalWebAcls(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting regional WAF Web Acl resource poller")

	// Get regional ACLs for Application Load balancers and API gateways using WAF Regional API
	var resources []*apimodels.AddResourceEntry
	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "waf-regional") {
		wafRegionalSvc, err := getWafRegionalClient(pollerInput, *regionID)
		if err != nil {
			continue // error is logged in getClient()
		}

		// Start with generating a list of all regional web acls
		regionalWebACLsSummaries := listWebAcls(wafRegionalSvc)
		if len(regionalWebACLsSummaries) == 0 {
			zap.L().Debug("No WAF Regional web ACLs found.", zap.String("region", *regionID))
			continue
		}

		for _, regionalWebACL := range regionalWebACLsSummaries {
			regionalWebACLSnapshot := buildWafWebACLSnapshot(wafRegionalSvc, regionalWebACL.WebACLId)
			if regionalWebACLSnapshot == nil {
				continue
			}
			regionalWebACLSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
			regionalWebACLSnapshot.Region = regionID
			regionalWebACLSnapshot.ResourceType = aws.String(awsmodels.WafRegionalWebAclSchema)

			resources = append(resources, &apimodels.AddResourceEntry{
				Attributes:      regionalWebACLSnapshot,
				ID:              apimodels.ResourceID(*regionalWebACLSnapshot.ARN),
				IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
				IntegrationType: apimodels.IntegrationTypeAws,
				Type:            awsmodels.WafRegionalWebAclSchema,
			})
		}
	}

	return resources, nil
}

// PollWafWebAcls gathers information on each Web ACL for an AWS account.
func PollWafWebAcls(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting global WAF Web Acl resource poller")

	// Get global ACLs for CloudFront distribution using WAF API
	wafSvc, err := getWafClient(pollerInput, defaultRegion)
	if err != nil {
		return nil, err // error is logged in getClient()
	}

	// Start with generating a list of all global web acls
	globalWebAclsSummaries := listWebAcls(wafSvc)
	var resources []*apimodels.AddResourceEntry
	for _, webACL := range globalWebAclsSummaries {
		webACLSnapshot := buildWafWebACLSnapshot(wafSvc, webACL.WebACLId)
		if webACLSnapshot == nil {
			continue
		}
		webACLSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)
		webACLSnapshot.Region = aws.String(awsmodels.GlobalRegion)
		webACLSnapshot.ResourceType = aws.String(awsmodels.WafWebAclSchema)

		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      webACLSnapshot,
			ID:              apimodels.ResourceID(*webACLSnapshot.ARN),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.WafWebAclSchema,
		})
	}

	return resources, nil
}
