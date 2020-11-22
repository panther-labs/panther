package manager

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
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
)

const (
	layerPath    = "python/lib/python3.7/site-packages/"
	layerRuntime = "python3.7"
)

var (
	globalLayerName  = aws.String(os.Getenv("GLOBAL_LAYER_NAME"))
	globalLayerArn   = aws.String(os.Getenv("GLOBAL_LAYER_ARN"))
	policyEngineName = aws.String(os.Getenv("POLICY_ENGINE"))
	ruleEngineName   = aws.String(os.Getenv("RULE_ENGINE"))
)

// UpdateLayer rebuilds and publishes the layer for the given analysis type.
// Currently global is the only supported analysis type.
func UpdateLayer(analysisType string) error {
	if analysisType != string(models.TypeGlobal) {
		zap.L().Warn("unsupported analysis type", zap.String("type", analysisType))
		// When we add support for policies/rules, we can use this variable to control which layers are re-created
		// and from which sources. We can either have entirely separate paths for these, or have some sort of config
		// stored that records the different names, paths, etc. mapped to the different analysis types.
		return errors.New("cannot build layer for unsupported analysisType " + analysisType)
	}

	newLayer, err := buildLayer()
	if err != nil {
		return err
	}

	if newLayer == nil {
		return removeGlobalLayer()
	}

	layerArn, layerVersion, err := publishLayer(newLayer)
	if err != nil {
		return err
	}

	// For policy/rule layers, only do one of these
	err = updateLambda(policyEngineName, layerArn, layerVersion)
	if err != nil {
		return err
	}

	err = updateLambda(ruleEngineName, layerArn, layerVersion)
	if err != nil {
		return err
	}

	return consolidateLayerVersions(layerArn, layerVersion)
}

// buildLayer looks up the required analyses and from them constructs the zip archive that defines the layer
func buildLayer() ([]byte, error) {
	zap.L().Debug("building lambda layer")
	// TODO: talk to the analysis-api GetEnabledPolicies endpoint and build the layer for policies/rules
	// be sure to have a means of differentiating the resource/log type of each policy/rule

	globals, err := listAllGlobals()
	if err != nil {
		return nil, err
	}

	// If there are no globals, delete the layer
	if len(globals) == 0 {
		return nil, nil
	}

	zap.L().Debug("getting each global")
	nameBodyMap := make(map[string]string)
	// Iterate through each global and retrieve its body
	for _, globalName := range globals {
		zap.L().Debug("getting global", zap.String("id", globalName))
		input := models.LambdaInput{
			GetGlobal: &models.GetGlobalInput{ID: globalName},
		}
		var global models.Global

		if _, err := analysisClient.Invoke(&input, &global); err != nil {
			return nil, err
		}

		nameBodyMap[globalName] = global.Body
	}

	return packageLayer(nameBodyMap)
}

func listAllGlobals() ([]string, error) {
	var names []string
	page := 1

	zap.L().Debug("listing all globals")
	for {
		input := models.LambdaInput{
			ListGlobals: &models.ListGlobalsInput{Page: page},
		}
		var globals models.ListGlobalsOutput
		if _, err := analysisClient.Invoke(&input, &globals); err != nil {
			return nil, err
		}

		for _, global := range globals.Globals {
			names = append(names, global.ID)
		}
		if globals.Paging.ThisPage < globals.Paging.TotalPages {
			page++
		} else {
			break
		}
	}
	zap.L().Debug("done listing all globals")

	return names, nil
}

// packageLayer takes a mapping of filenames to function bodies and constructs a zip archive with the file structure
// that AWS is expecting.
func packageLayer(analyses map[string]string) ([]byte, error) {
	zap.L().Debug("packaging lambda layer")
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	for id, body := range analyses {
		f, err := w.Create(layerPath + id + ".py")
		if err != nil {
			return nil, err
		}
		_, err = f.Write([]byte(body))
		if err != nil {
			return nil, err
		}
	}

	err := w.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// removeGlobalLayer removes the global layer from policy and rule engines
func removeGlobalLayer() error {
	err := updateLambda(policyEngineName, globalLayerArn, nil)
	if err != nil {
		return err
	}
	err = updateLambda(ruleEngineName, globalLayerArn, nil)
	if err != nil {
		return err
	}
	return consolidateLayerVersions(globalLayerName, nil)
}

// consolidateLayerVersions deletes all versions of a layer except for the given version, in order to make sure we
// don't go over the regional lambda limit (which layers count against)
func consolidateLayerVersions(layerName *string, layerVersion *int64) error {
	versions, err := lambdaClient.ListLayerVersions(&lambda.ListLayerVersionsInput{
		LayerName: layerName,
	})
	if err != nil {
		return err
	}
	for _, version := range versions.LayerVersions {
		if aws.Int64Value(version.Version) == aws.Int64Value(layerVersion) {
			continue
		}
		_, err := lambdaClient.DeleteLayerVersion(&lambda.DeleteLayerVersionInput{
			LayerName:     layerName,
			VersionNumber: version.Version,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// publishLayer takes a zip file and publishes it as a new lambda layer. It returns both the layer ARN and the layer
// ARN with version, for simplicity's sake.
func publishLayer(layerBody []byte) (*string, *int64, error) {
	zap.L().Debug("publishing lambda layer")
	layer, err := lambdaClient.PublishLayerVersion(&lambda.PublishLayerVersionInput{
		CompatibleRuntimes: []*string{aws.String(layerRuntime)},
		Content: &lambda.LayerVersionContentInput{
			ZipFile: layerBody,
		},
		Description: aws.String("The panther engine global helper layer."),
		LayerName:   globalLayerName,
	})
	if err != nil {
		return nil, nil, err
	}
	return layer.LayerArn, layer.Version, nil
}

// updateLambda updates the function configuration of a given lambda to include the specified lambda layer.
// The layer is updated to the given version if it is already present.
func updateLambda(lambdaName, layerArn *string, layerVersion *int64) error {
	zap.L().Debug(
		"updating lambda function with new layer",
		zap.String("lambda", aws.StringValue(lambdaName)),
		zap.String("layer", aws.StringValue(layerArn)),
		zap.Int64("version", aws.Int64Value(layerVersion)),
	)
	// Lambda does not let you update just one layer on a lambda, you must specify the name of each desired layer so
	// we start by listing what layers are already present to preserve them.
	oldLayers, err := lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: lambdaName,
	})
	if err != nil {
		return err
	}

	// Replace the layer we want to update with the new layer
	//
	// Append the version to the ARN to get the versioned layer ARN
	newLayerVersionArn := aws.StringValue(layerArn) + ":" + strconv.FormatInt(aws.Int64Value(layerVersion), 10)
	var newLayers []*string
	replaced := false
	for _, layer := range oldLayers.Layers {
		if strings.HasPrefix(*layer.Arn, *layerArn) {
			if layerVersion != nil {
				// Update operation
				newLayers = append(newLayers, aws.String(newLayerVersionArn))
			}
			replaced = true
		} else {
			newLayers = append(newLayers, layer.Arn)
		}
	}

	// Handle the case where we are not updating or deleting an existing layer
	if !replaced && layerVersion != nil {
		zap.L().Debug("no lambda layer to replace")
		newLayers = append(newLayers, aws.String(newLayerVersionArn))
	}

	// Update the lambda function. This operation may take 1-3 seconds.
	_, err = lambdaClient.UpdateFunctionConfiguration(&lambda.UpdateFunctionConfigurationInput{
		FunctionName: lambdaName,
		Layers:       newLayers,
	})

	return err
}
