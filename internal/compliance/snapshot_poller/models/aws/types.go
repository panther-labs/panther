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
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/arn"

	resourcesapimodels "github.com/panther-labs/panther/api/lambda/resources/models"
)

// Used to populate the GenericAWSResource.Region field for global AWS resources
const GlobalRegion = "global"

// GenericResource contains fields that will be common to all resources, at some point this will
// probably exist in a more global package but for now since this is the only poller it will exist
// here.
type GenericResource struct {
	ResourceID   *string    `json:"ResourceId"`   // A panther wide unique identifier
	ResourceType *string    `json:"ResourceType"` // A panther defined resource type
	TimeCreated  *time.Time `json:"TimeCreated"`  // A standardized format for when the resource was created
}

// GenericAWSResource contains information that is standard across AWS resources
type GenericAWSResource struct {
	//
	// The fields ARN, ID, and Name are tagged omitempty so that those fields will not exist in the
	// down stream python resources if they are not populated, as those fields will either always
	// exist or never exist for a given resource type.
	//
	// This is in contrast to the fields AccountID and Region which will always exist and should therefore
	// always be sent downstream, and the field Tags which may or may not exist for a specific
	// resource of a given resource type and should therefore always be sent downstream, even if
	// only as an empty list.
	//

	// Fields that generally need to be populated after building the snapshot
	AccountID *string `json:"AccountId"` // The ID of the AWS Account the resource resides in
	Region    *string `json:"Region"`    // The region the resource exists in, value of GLOBAL_REGION if global

	// Fields that can generally be populated while building the snapshot
	ARN  *string            `json:"Arn,omitempty"`  // The Amazon Resource Name (ARN)
	ID   *string            `json:"Id,omitempty"`   // The AWS resource identifier
	Name *string            `json:"Name,omitempty"` // The AWS resource name
	Tags map[string]*string // A standardized format for key/value resource tags
}

// ResourcePollerInput contains the metadata to request AWS resource info.
type ResourcePollerInput struct {
	AuthSource              *string
	AuthSourceParsedARN     arn.ARN
	IntegrationID           *string
	Region                  *string
	Timestamp               *time.Time
	NextPageToken           *string
	RegionIgnoreList        []string
	ResourceTypeIgnoreList  []string
	ResourceRegexIgnoreList []string
	CompiledRegexIgnoreList []*regexp.Regexp
}

func (r *ResourcePollerInput) CompileRegex() error {
	r.CompiledRegexIgnoreList = make([]*regexp.Regexp, 0, len(r.ResourceRegexIgnoreList))

	for _, glob := range r.ResourceRegexIgnoreList {
		if glob == "" {
			continue
		}
		// First,  escape any regex special characters
		escaped := regexp.QuoteMeta(glob)

		// Wildcards in the original pattern are now escaped literals - convert back
		// NOTE: currently no way for user to specify a glob that would match a literal '*'
		regex := "^" + strings.ReplaceAll(escaped, `\*`, `.*`) + "$"
		compiledGlob, err := regexp.Compile(regex)
		if err != nil {
			return err
		}
		r.CompiledRegexIgnoreList = append(r.CompiledRegexIgnoreList, compiledGlob)
	}
	return nil
}

func (r *ResourcePollerInput) ShouldIgnoreResource(resourceID string) (ignore bool) {
	for _, compiledRegex := range r.CompiledRegexIgnoreList {
		if compiledRegex.MatchString(resourceID) {
			return true
		}
	}
	return false
}

// ResourcePoller represents a function to poll a specific AWS resource.
type ResourcePoller func(input *ResourcePollerInput) ([]resourcesapimodels.AddResourceEntry, *string, error)
