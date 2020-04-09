package mage

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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/tools/cfndoc"
	"github.com/panther-labs/panther/tools/cfngen/cloudwatchcf"
	"github.com/panther-labs/panther/tools/cfngen/gluecf"
	"github.com/panther-labs/panther/tools/config"
	"github.com/panther-labs/panther/tools/dashboards"
)

// Generate Glue tables for log processor output as CloudFormation
func generateGlueTables() error {
	outDir := filepath.Dir(glueTemplate)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", outDir, err)
	}

	glueCfFile, err := os.Create(glueTemplate)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", glueTemplate, err)
	}
	defer glueCfFile.Close()

	tableResources := registry.AvailableTables()
	logger.Debugf("deploy: cfngen: loaded %d glue tables", len(tableResources))
	cf, err := gluecf.GenerateTables(tableResources)
	if err != nil {
		return fmt.Errorf("failed to generate Glue Data Catalog CloudFormation template: %v", err)
	}

	if _, err = glueCfFile.Write(cf); err != nil {
		return fmt.Errorf("failed to write file %s: %v", glueTemplate, err)
	}
	return nil
}

// Generate CloudWatch dashboards as CloudFormation
func generateDashboards() error {
	outDir := filepath.Join("out", "deployments", "monitoring")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", outDir, err)
	}
	dashboardsCfFileName := filepath.Join(outDir, "dashboards.json")

	dashboardsCfFile, err := os.Create(dashboardsCfFileName)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", dashboardsCfFileName, err)
	}
	defer dashboardsCfFile.Close()

	dashboardResources := dashboards.Dashboards()
	logger.Debugf("deploy: cfngen: loaded %d dashboards", len(dashboardResources))
	cf, err := cloudwatchcf.GenerateDashboards(dashboardResources)
	if err != nil {
		return fmt.Errorf("failed to generate dashboard CloudFormation template: %v", err)
	}

	if _, err = dashboardsCfFile.Write(cf); err != nil {
		return fmt.Errorf("failed to write file %s: %v", dashboardsCfFileName, err)
	}
	return nil
}

// Generate CloudWatch alarms as CloudFormation
func generateAlarms(settings *config.PantherConfig) error {
	var alarms []*cloudwatchcf.Alarm

	outDir := filepath.Join("out", "deployments", "monitoring")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", outDir, err)
	}

	// loop over deployment CF files generating alarms for each
	for _, cfFile := range cfnFiles() {
		logger.Debugf("generating alarm cloudformation for %s", cfFile)
		alarmsCfBasename := strings.TrimSuffix(filepath.Base(cfFile), ".yml") + "_alarms.json"
		alarmsCfFilePath := filepath.Join(outDir, alarmsCfBasename) // where we will write

		// generate alarms
		fileAlarms, cf, err := cloudwatchcf.GenerateAlarms(settings, cfFile)
		if err != nil {
			return fmt.Errorf("failed to generate alarms CloudFormation template %s: %v", alarmsCfFilePath, err)
		}
		if len(fileAlarms) == 0 {
			logger.Debugf("no alarms for %s", cfFile)
			continue
		}

		alarms = append(alarms, fileAlarms...) // save for validation

		// write cf to file
		alarmsCfFile, err := os.Create(alarmsCfFilePath)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %v", alarmsCfFilePath, err)
		}
		if _, err = alarmsCfFile.Write(cf); err != nil {
			return fmt.Errorf("failed to write file %s: %v", alarmsCfFilePath, err)
		}
		alarmsCfFile.Close()
	}

	// confirm all alarms generated are documented by cfndoc tags
	resourceLookup := resourceDocumentation()
	failedValidation := false
	for _, alarm := range alarms {
		if _, found := resourceLookup[alarm.Resource]; !found {
			logger.Errorf("resource %s is missing cfndoc for alarm %s", alarm.Resource, alarm.Properties.AlarmName)
			failedValidation = true
		}
	}
	if failedValidation {
		logger.Fatal("all alarms must be documented")
	}

	return nil
}

// return a map to look up if a resource has associated cfndoc documentation
func resourceDocumentation() (resourceLookup map[string]struct{}) {
	docs, err := cfndoc.ReadCfn(cfnFiles()...)
	if err != nil {
		logger.Fatalf("failed to generate operational documentation: %v", err)
	}
	resourceLookup = make(map[string]struct{})
	for _, doc := range docs {
		resourceLookup[doc.Resource] = struct{}{}
	}
	return resourceLookup
}

// Generate CloudWatch metrics as CloudFormation
func generateMetrics() error {
	outDir := filepath.Join("out", "deployments", "monitoring")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", outDir, err)
	}
	metricsCfFileName := filepath.Join(outDir, "metrics.json")

	metricsCfFile, err := os.Create(metricsCfFileName)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", metricsCfFileName, err)
	}
	defer metricsCfFile.Close()

	cf, err := cloudwatchcf.GenerateMetrics(cfnFiles()...)
	if err != nil {
		return fmt.Errorf("failed to generate metrics CloudFormation template: %v", err)
	}

	if _, err = metricsCfFile.Write(cf); err != nil {
		return fmt.Errorf("failed to write file %s: %v", metricsCfFileName, err)
	}
	return nil
}
