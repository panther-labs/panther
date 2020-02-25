package cloudwatchcf

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

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

func walkYamlFiles(cfDir string, generatorFunc func(string) error) error {
	return filepath.Walk(cfDir, func(path string, info os.FileInfo, fileErr error) error {
		if fileErr != nil {
			return errors.Wrap(fileErr, path)
		}
		if info.IsDir() { // skip dirs
			return nil
		}
		err := generatorFunc(path)
		if err != nil {
			return errors.Wrap(err, path)
		}
		return nil
	})
}

type YamlDispatcher func(resourceType string, resource map[interface{}]interface{})

// walk the tree, apply dispatcher on each resource based on Type
func walkYamlMap(yamlObj interface{}, dispatcher YamlDispatcher) {
	switch objVal := yamlObj.(type) {
	case map[interface{}]interface{}:
		for k, v := range objVal {
			switch keyVal := k.(type) {
			case string:
				switch keyVal {
				case "Type":
					switch valVal := v.(type) {
					case string:
						dispatcher(valVal, objVal)
					}
				}
				walkYamlMap(v, dispatcher)
			}
		}
	case []interface{}:
		for i := range objVal {
			walkYamlMap(objVal[i], dispatcher)
		}
	}
}

func readYaml(fileName string) (yamlObj interface{}, err error) {
	fh, err := os.Open(fileName)
	if err != nil {
		return nil, errors.Wrap(err, fileName)
	}

	inputCf, err := ioutil.ReadAll(fh)
	if err != nil {
		return nil, errors.Wrap(err, fileName)
	}

	err = yaml.Unmarshal(inputCf, &yamlObj)
	if err != nil {
		return nil, errors.Wrap(err, fileName)
	}

	return yamlObj, nil
}
