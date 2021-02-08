package handlers

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
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	validate "gopkg.in/go-playground/validator.v9"
	"gopkg.in/yaml.v2"

	"github.com/panther-labs/panther/api/lambda/analysis"
	"github.com/panther-labs/panther/api/lambda/analysis/models"
	compliancemodels "github.com/panther-labs/panther/api/lambda/compliance/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

type writeResult struct {
	item       *tableItem
	changeType int
	err        error
}

// BulkUpload uploads multiple analysis items from a zipfile.
func (API) BulkUpload(input *models.BulkUploadInput) *events.APIGatewayProxyResponse {
	policies, err := extractZipFile(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body:       err.Error(),
			StatusCode: http.StatusBadRequest,
		}
	}

	// Create/modify each policy in parallel
	results := make(chan writeResult)
	for _, policy := range policies {
		go func(item *tableItem) {
			defer func() {
				// Recover from panic so we don't block forever when waiting for routines to finish.
				if r := recover(); r != nil {
					zap.L().Error("panicked while processing item",
						zap.String("id", item.ID), zap.Any("panic", r))
					results <- writeResult{err: errors.New("panicked goroutine")}
				}
			}()
			changeType, err := writeItem(item, input.UserID, nil)
			results <- writeResult{item: item, changeType: changeType, err: err}
		}(policy)
	}

	var counts models.BulkUploadOutput
	var response *events.APIGatewayProxyResponse

	// Wait for all the goroutines to finish.
	for range policies {
		result := <-results
		if result.err != nil {
			// Set the response with an error code - 4XX first, otherwise 5XX
			if result.err == errWrongType {
				err := errors.Errorf("ID %s does not have expected type %s", result.item.ID, result.item.Type)
				response = &events.APIGatewayProxyResponse{
					Body:       err.Error(),
					StatusCode: http.StatusConflict,
				}
			} else if response == nil {
				// errExists and errNotExists do not apply here  -
				// bulk upload automatically creates or updates depending on whether it already exists
				response = &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
			}

			continue
		}

		switch result.item.Type {
		case models.TypePolicy:
			counts.TotalPolicies++
			if result.changeType == newItem {
				counts.NewPolicies++
			} else if result.changeType == updatedItem {
				counts.ModifiedPolicies++
			}

		case models.TypeRule:
			counts.TotalRules++
			if result.changeType == newItem {
				counts.NewRules++
			} else if result.changeType == updatedItem {
				counts.ModifiedRules++
			}

		case models.TypeGlobal:
			counts.TotalGlobals++
			if result.changeType == newItem {
				counts.NewGlobals++
			} else if result.changeType == updatedItem {
				counts.ModifiedGlobals++
			}

		case models.TypeDataModel:
			counts.TotalDataModels++
			if result.changeType == newItem {
				counts.NewDataModels++
			} else if result.changeType == updatedItem {
				counts.ModifiedDataModels++
			}

		default:
			response = &events.APIGatewayProxyResponse{
				Body:       "unknown detection type " + string(result.item.Type),
				StatusCode: http.StatusBadRequest,
			}
		}
	}

	// If at least one global was created or modified, rebuild the global layer
	if counts.TotalGlobals > 0 {
		err = updateLayer()
		if err != nil {
			return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
		}
	}

	if response != nil {
		return response
	}
	return gatewayapi.MarshalResponse(&counts, http.StatusOK)
}

func extractZipFile(input *models.BulkUploadInput) (map[string]*tableItem, error) {
	// Base64-decode
	content, err := base64.StdEncoding.DecodeString(input.Data)
	if err != nil {
		return nil, errors.Errorf("base64 decoding failed: %s", err)
	}

	// Unzip in memory (the max request size is only 6 MB, so this should easily fit)
	zipReader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return nil, errors.Errorf("zipReader failed: %s", err)
	}

	policyBodies := make(map[string]string) // map base file name to contents
	result := make(map[string]*tableItem)

	logtypes, err := getLogTypesSet()
	if err != nil {
		return nil, errors.Wrap(err, "BulkUpload extractZipFile getLogTypesSet")
	}

	// Process each file
	for _, zipFile := range zipReader.File {
		if strings.HasSuffix(zipFile.Name, "/") {
			continue // skip directories (we will see their nested files next)
		}

		unzippedBytes, err := readZipFile(zipFile)
		if err != nil {
			return nil, errors.Errorf("file extraction failed: %s: %s", zipFile.Name, err)
		}

		if strings.Contains(zipFile.Name, "__pycache__") {
			continue
		}

		var config analysis.Config

		switch strings.ToLower(filepath.Ext(zipFile.Name)) {
		case ".py":
			// Store the Python body to be referenced later
			policyBodies[filepath.Base(zipFile.Name)] = string(unzippedBytes)
			continue
		case ".json":
			err = jsoniter.Unmarshal(unzippedBytes, &config)
		case ".yml", ".yaml":
			err = yaml.Unmarshal(unzippedBytes, &config)
		default:
			zap.L().Debug("skipped unsupported file", zap.String("fileName", zipFile.Name))
		}
		if err != nil {
			return nil, err
		}

		// Check for invalid log or resource types
		err = bulkValidateLogAndResourceTypes(config, logtypes)
		if err != nil {
			return nil, err
		}

		// Map the Config struct fields over to the fields we need to store in Dynamo
		analysisItem := tableItemFromConfig(config)

		if analysisItem.Type == models.TypeDataModel {
			// ensure Mappings are nil rather than an empty slice
			if len(config.Mappings) > 0 {
				analysisItem.Mappings = make([]models.DataModelMapping, len(config.Mappings))
				for i, mapping := range config.Mappings {
					analysisItem.Mappings[i], err = buildMapping(mapping)
					if err != nil {
						return nil, err
					}
				}
			}
			// ensure only one data model is enabled per LogType (ResourceType)
			err = validateUploadedDataModel(analysisItem)
			if err != nil {
				return nil, err
			}
		}

		for i, test := range config.Tests {
			// A test can specify a resource and a resource type or a log and a log type.
			// By convention, log and log type are used for rules and resource and resource type are used for policies.
			if test.Resource == nil {
				analysisItem.Tests[i], err = buildRuleTest(test)
			} else {
				analysisItem.Tests[i], err = buildPolicyTest(test)
			}
			if err != nil {
				return nil, err
			}
		}

		if _, exists := result[analysisItem.ID]; exists {
			return nil, errors.Errorf("multiple analysis specs with ID %s", analysisItem.ID)
		}
		result[analysisItem.ID] = analysisItem
	}

	// Finish each policy by adding its body and then validate it
	for _, policy := range result {
		if body, ok := policyBodies[policy.Body]; ok {
			policy.Body = body
			if err := validateUploadedPolicy(policy); err != nil {
				return nil, err
			}
		} else if policy.Type != models.TypeDataModel {
			// it is ok for DataModels to be missing python body
			return nil, errors.Errorf("policy %s is missing a body", policy.ID)
		}
	}

	return result, nil
}

func buildMapping(mapping analysis.Mapping) (models.DataModelMapping, error) {
	var result models.DataModelMapping
	if mapping.Path != "" && mapping.Method != "" {
		return result, errMappingTooManyOptions
	}
	if mapping.Path == "" && mapping.Method == "" {
		return result, errPathOrMethodMissing
	}
	return models.DataModelMapping{
		Name:   mapping.Name,
		Path:   mapping.Path,
		Method: mapping.Method,
	}, nil
}

func buildPolicyTest(test analysis.Test) (models.UnitTest, error) {
	resource, err := jsoniter.MarshalToString(test.Resource)
	return models.UnitTest{
		ExpectedResult: test.ExpectedResult,
		Name:           test.Name,
		Resource:       resource,
	}, err
}

func buildRuleTest(test analysis.Test) (models.UnitTest, error) {
	log, err := jsoniter.MarshalToString(test.Log)
	return models.UnitTest{
		ExpectedResult: test.ExpectedResult,
		Name:           test.Name,
		Resource:       log,
	}, err
}

// Validate the analysis item's Resource type or Log type depending on the config AnalysisType.
// Passing the logtypes allows us to retrieve the set of valid log types once for a set of validations
func bulkValidateLogAndResourceTypes(config analysis.Config, logtypes map[string]struct{}) error {
	itemType := models.DetectionType(strings.ToUpper(config.AnalysisType))
	resourceTypes := config.ResourceTypes
	switch itemType {
	case models.TypeDataModel, models.TypeRule:
		if len(resourceTypes) == 0 {
			resourceTypes = config.LogTypes
		}
		invalidRsc := FirstSetItemNotInMapKeys(resourceTypes, logtypes)
		if len(invalidRsc) > 0 {
			itemTitle := "DataModel"
			if itemType == models.TypeRule {
				itemTitle = "Rule"
			}
			return errors.Errorf("%s %s contains invalid log type: %s", itemTitle, config.DisplayName, invalidRsc)
		}
	case models.TypePolicy:
		if err := validResourceTypeSet(resourceTypes); err != nil {
			return errors.Errorf("Policy %s contains invalid log type: %s", config.DisplayName, err.Error())
		}
	}
	return nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	f, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			zap.L().Info("error closing zip file", zap.Error(err))
		}
	}()
	return ioutil.ReadAll(f)
}

func tableItemFromConfig(config analysis.Config) *tableItem {
	item := tableItem{
		AutoRemediationID:         config.AutoRemediationID,
		AutoRemediationParameters: config.AutoRemediationParameters,

		// Use filename as placeholder for the body which we lookup later
		Body: config.Filename,

		Description:   config.Description,
		DisplayName:   config.DisplayName,
		Enabled:       config.Enabled,
		ID:            config.PolicyID,
		OutputIDs:     config.OutputIds,
		Reference:     config.Reference,
		ResourceTypes: config.ResourceTypes,
		Runbook:       config.Runbook,
		Severity:      compliancemodels.Severity(strings.ToUpper(config.Severity)),
		Suppressions:  config.Suppressions,
		Tags:          config.Tags,
		Tests:         make([]models.UnitTest, len(config.Tests)),
		Type:          models.DetectionType(strings.ToUpper(config.AnalysisType)),
		Reports:       config.Reports,
		Threshold:     config.Threshold,
	}

	switch item.Type {
	case models.TypeRule:
		// If there is no value set, default to 60 minutes
		if config.DedupPeriodMinutes == 0 {
			item.DedupPeriodMinutes = defaultDedupPeriodMinutes
		} else {
			item.DedupPeriodMinutes = config.DedupPeriodMinutes
		}

		// If there is no value set, default to 1
		if config.Threshold == 0 {
			item.Threshold = defaultRuleThreshold
		} else {
			item.Threshold = config.Threshold
		}

		// These "syntax sugar" re-mappings are to make managing rules from the CLI more intuitive
		if config.PolicyID == "" {
			item.ID = config.RuleID
		}
		if len(config.ResourceTypes) == 0 {
			item.ResourceTypes = config.LogTypes
		}

	case models.TypeGlobal:
		item.ID = config.GlobalID
		// Support non-ID'd globals as the 'panther' global
		if item.ID == "" {
			item.ID = "panther"
		}

	case models.TypeDataModel:
		item.ID = config.DataModelID
		if len(config.ResourceTypes) == 0 {
			item.ResourceTypes = config.LogTypes
		}
	}

	return &item
}

// Data Model Validations: len(ResourceTypes) <= 1, Single Model Enabled
func validateUploadedDataModel(item *tableItem) error {
	if len(item.ResourceTypes) > 1 {
		return errors.New("only one LogType may be specified per DataModel")
	}
	isEnabled, err := isSingleDataModelEnabled(item.ID, item.Enabled, item.ResourceTypes)
	if err != nil {
		return err
	}
	if !isEnabled {
		return errMultipleDataModelsEnabled
	}
	return nil
}

// Ensure that the uploaded policy is valid according to the API spec for a Policy
func validateUploadedPolicy(item *tableItem) error {
	switch item.Type {
	case models.TypeGlobal:
		item.Severity = compliancemodels.SeverityInfo
	case models.TypeDataModel:
		item.Severity = compliancemodels.SeverityInfo
	case models.TypePolicy, models.TypeRule:
		break
	default:
		return errors.Errorf("policy ID %s is invalid: unknown analysis type %s", item.ID, item.Type)
	}

	// Convert to the external Policy model for validation
	policy := item.Policy(compliancemodels.StatusPass)
	if err := validate.New().Struct(policy); err != nil {
		return errors.Errorf("policy ID %s is invalid: %s", policy.ID, err)
	}
	return nil
}
