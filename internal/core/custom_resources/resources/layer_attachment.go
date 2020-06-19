package resources

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
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/service/lambda"
	"go.uber.org/zap"
)

type LayerAttachmentProperties struct {
	FunctionArn *string
	LayerArns   []*string
}

func customLayerAttachment(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		x, y, z := handleCreateUpdateRequests(event)
		if z != nil {
		}
		return x, y, z
	case cfn.RequestDelete:
		return handleDeleteRequests(event)
	default:
		return "", nil, fmt.Errorf("unknown request type %s", event.RequestType)
	}
}

func handleCreateUpdateRequests(event cfn.Event) (string, map[string]interface{}, error) {
	var newProps LayerAttachmentProperties
	// Parse the properties
	if err := parseProperties(event.ResourceProperties, &newProps); err != nil {
		return "", nil, err
	}
	// Separate the version so we can do string comparisons
	newLayers, err := extractToLayers(newProps.LayerArns)
	if err != nil {
		return "", nil, err
	}

	// Repeat for the old state
	var oldProps LayerAttachmentProperties
	if err := parseProperties(event.OldResourceProperties, &oldProps); err != nil {
		return "", nil, err
	}
	oldLayers, err := extractToLayers(oldProps.LayerArns)
	if err != nil {
		return "", nil, err
	}

	// Lambda does not allow partial updates to the function layer configuration, so we need to
	// look up any existing layers
	response, err := lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: newProps.FunctionArn,
	})
	if err != nil {
		return "", nil, err
	}

	// Insert/update/remove layers as appropriate

	// First determine if there are any existing layers that need to be removed
	var layersToRemove []*Layer
	for _, layer := range oldLayers {
		found := false
		for _, newLayer := range newLayers {
			if layer.Arn == newLayer.Arn {
				found = true
				break
			}
		}
		if !found {
			layersToRemove = append(layersToRemove, layer)
		}
	}

	var finalLayers []*string
	// Add all the new layers because we know we want them
	for _, layer := range newLayers {
		versionedArn := layer.Arn + ":" + strconv.Itoa(layer.Version)
		finalLayers = append(finalLayers, &versionedArn)
	}

	// Add every existing layer that we don't need to remove
	for _, existingLayer := range response.Layers {
		// Filter out what we know needs to be removed
		skip := false
		for _, removedLayer := range layersToRemove {
			if strings.HasPrefix(*existingLayer.Arn, removedLayer.Arn) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Determine which layers may need to be maintained
		keep := true
		for _, newLayer := range newLayers {
			if strings.HasPrefix(*existingLayer.Arn, newLayer.Arn) {
				keep = false
				break
			}
		}
		if keep {
			finalLayers = append(finalLayers, existingLayer.Arn)
		}
	}

	zap.L().Info("adding layers", zap.Any("finalLayers", finalLayers))
	_, err = lambdaClient.UpdateFunctionConfiguration(&lambda.UpdateFunctionConfigurationInput{
		FunctionName: newProps.FunctionArn,
		Layers:       finalLayers,
	})
	if err != nil {
		return "", nil, err
	}

	resourceID := fmt.Sprintf("custom:lambda:layerattachment:%s",
		*newProps.FunctionArn)

	return resourceID, nil, nil
}

func handleDeleteRequests(event cfn.Event) (string, map[string]interface{}, error) {
	split := strings.Split(event.PhysicalResourceID, ":")
	if len(split) < 4 {
		// invalid resourceID (e.g. CREATE_FAILED) - skip delete
		return event.PhysicalResourceID, nil, nil
	}
	var props LayerAttachmentProperties
	if err := parseProperties(event.ResourceProperties, &props); err != nil {
		return "", nil, err
	}
	// Separate the version so we can do string comparisons
	layersToRemove, err := extractToLayers(props.LayerArns)
	if err != nil {
		return "", nil, err
	}

	// Lambda does not allow partial updates to the function layer configuration, so we need to
	// look up any existing layers
	response, err := lambdaClient.GetFunctionConfiguration(&lambda.GetFunctionConfigurationInput{
		FunctionName: props.FunctionArn,
	})
	// Function is probably already deleted, so just exit
	if err != nil {
		return event.PhysicalResourceID, nil, err
	}

	var finalLayers []*string
	for _, existingLayer := range response.Layers {
		// Filter out what we know needs to be removed
		keep := true
		for _, layer := range layersToRemove {
			if strings.HasPrefix(*existingLayer.Arn, layer.Arn) {
				keep = false
				break
			}
		}
		if keep {
			finalLayers = append(finalLayers, existingLayer.Arn)
		}
	}

	_, err = lambdaClient.UpdateFunctionConfiguration(&lambda.UpdateFunctionConfigurationInput{
		FunctionName: props.FunctionArn,
		Layers:       finalLayers,
	})
	return event.PhysicalResourceID, nil, err
}

type Layer struct {
	Arn     string
	Version int
}

func extractToLayers(layerArns []*string) ([]*Layer, error) {
	var layers []*Layer
	for _, layerArn := range layerArns {
		layer, err := extractLayerVersion(layerArn)
		if err != nil {
			return nil, err
		}
		layers = append(layers, layer)
	}

	return layers, nil
}

func extractLayerVersion(layerArn *string) (*Layer, error) {
	pieces := strings.Split(*layerArn, ":")
	version, err := strconv.Atoi(pieces[len(pieces)-1])
	if err != nil {
		return nil, err
	}
	arn := strings.Join(pieces[0:len(pieces)-1], ":")

	return &Layer{
		Arn:     arn,
		Version: version,
	}, nil
}
