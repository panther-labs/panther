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
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/cfn"
	"github.com/aws/aws-sdk-go/service/lambda"
	"go.uber.org/zap"
)

const latest = "LATEST"

type LayerAttachmentProperties struct {
	LayerArns []*string
}

func customLayerAttachment(_ context.Context, event cfn.Event) (string, map[string]interface{}, error) {
	switch event.RequestType {
	case cfn.RequestCreate, cfn.RequestUpdate:
		return handleCreateUpdateRequests(event)
	default:
		return event.PhysicalResourceID, nil, nil
	}
}

func handleCreateUpdateRequests(event cfn.Event) (string, map[string]interface{}, error) {
	var props LayerAttachmentProperties
	// Parse the properties
	err := parseProperties(event.ResourceProperties, &props)
	if err != nil {
		return "", nil, err
	}

	var layers []*string
	for _, layer := range props.LayerArns {
		pieces := strings.Split(*layer, ":")
		// Check if the version (the last section of the arn) is equal to latest
		version := pieces[len(pieces)-1]
		arn := strings.Join(pieces[0:len(pieces)-1], ":")
		if version == latest {
			version, err = getLatestLayerVersion(arn)
			if err != nil {
				return "", nil, err
			}
		}
		// This means the layer doesn't exist yet, the service that creates the layer will be
		// responsible for attaching it or the deploy will need to be run again
		if version == "" {
			continue
		}
		versionedArn := arn + ":" + version
		layers = append(layers, &versionedArn)
	}

	zap.L().Info("returning layers", zap.Any("finalLayers", layers))
	return "custom:lambda:layerattachment", map[string]interface{}{"LayerArns": layers}, nil
}

func getLatestLayerVersion(layerArn string) (string, error) {
	response, err := lambdaClient.ListLayerVersions(&lambda.ListLayerVersionsInput{
		LayerName: &layerArn,
	})
	if err != nil {
		return "", err
	}
	greatest := int64(-1)
	for _, layer := range response.LayerVersions {
		if *layer.Version > greatest {
			greatest = *layer.Version
		}
	}
	if greatest == -1 {
		return "", nil
	}
	return strconv.Itoa(int(greatest)), nil
}
