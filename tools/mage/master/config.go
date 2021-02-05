package master

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
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/panther-labs/panther/pkg/prompt"
)

const (
	defaultRootStackName = "panther"
	rootConfigHeader     = "# Root stack configuration - edit to configure your own parameter overrides\n\n"
)

var (
	defaultPipLayer = []string{"jsonpath-ng==1.5.2", "policyuniverse==1.3.2.2", "requests==2.23.0"}
	rootConfigPath  = filepath.Join("deployments", "root_config.yml")
)

// Developer configuration for the root stack
type RootConfig struct {
	RootStackName      string            `yaml:"RootStackName"`
	PipLayer           []string          `yaml:"PipLayer"`
	ParameterOverrides map[string]string `yaml:"ParameterOverrides"`
}

// Populate the config from the settings file, if available
func (c *RootConfig) Load() error {
	bytes, err := ioutil.ReadFile(rootConfigPath)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(bytes, c)
}

// Generate a default root config for developers - the user will be prompted for their email.
func (c *RootConfig) Gen() error {
	c.RootStackName = defaultRootStackName
	c.PipLayer = defaultPipLayer

	email := prompt.Read("First user email: ", prompt.EmailValidator)
	dev, err := user.Current()
	if err != nil {
		return err
	}
	c.ParameterOverrides = map[string]string{
		"CloudWatchLogRetentionDays": "14",
		"CompanyDisplayName":         "PantherDev",
		"FirstUserEmail":             email,
		"FirstUserGivenName":         strings.Title(dev.Username),
	}

	return nil
}

// Save the root stack config to a .gitignore'd file
func (c *RootConfig) Save() error {
	bytes, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(rootConfigPath, append([]byte(rootConfigHeader), bytes...), 0600)
}

// Generate / load root stack configuration.
//
// If the deployments/root_config.yml file exists, it is loaded and returned.
// Otherwise, the file will be created after prompting for the first user's email.
//
// The parameter file is not checked in so developers can safely keep a local config.
//
// We can't define parameter values by wrapping the root stack in another template
// because CFN doesn't allow multiple levels of stack imports. In other words, the root
// stack must not itself be a nested stack for us to be able to import v1.15 direct-stack
// deployments.
func buildRootConfig(log *zap.SugaredLogger) (*RootConfig, error) {
	config := new(RootConfig)
	if err := config.Load(); err == nil {
		if config.RootStackName == "" {
			return nil, fmt.Errorf("%s is not valid: RootStackName is empty", rootConfigPath)
		}
		log.Infof("loaded root stack config from %s", rootConfigPath)
		return config, nil
	} else if os.IsNotExist(err) {
		log.Infof("%s does not exist; creating it", rootConfigPath)
		if err = config.Gen(); err != nil {
			return nil, err
		}
		return config, config.Save()
	} else {
		// Config file exists, but some error opening it
		return nil, err
	}
}
