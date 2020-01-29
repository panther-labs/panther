package athenaviews

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

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"

	"github.com/panther-labs/panther/internal/log_analysis/log_processor/parsers"
	"github.com/panther-labs/panther/internal/log_analysis/log_processor/registry"
	"github.com/panther-labs/panther/pkg/awsathena"
	"github.com/panther-labs/panther/pkg/awsglue"
	"github.com/panther-labs/panther/tools/cfngen/gluecf"
)

// CreateOrReplaceViews will update Athena with all views in the Panther view database
func CreateOrReplaceViews(athenaResultsBucket string) (err error) {
	sess, err := session.NewSession()
	if err != nil {
		return errors.Wrap(err, "CreateOrReplaceViews() failed")
	}
	s3Path := "s3://" + athenaResultsBucket + "/athena/"
	sqlStatements := GenerateViews(registry.AvailableTables())
	for _, sql := range sqlStatements {
		q := awsathena.NewAthenaQuery(sess, awsglue.ViewsDatabaseName, sql, &s3Path) // use default bucket
		err = q.Run()
		if err != nil {
			return errors.Wrap(err, "CreateOrReplaceViews() failed")
		}
		err = q.Wait()
		if err != nil {
			return errors.Wrap(err, "CreateOrReplaceViews() failed")
		}
	}
	return err
}

// GenerateViews creates useful Athena views in the panther views database
func GenerateViews(tables []*awsglue.GlueMetadata) (sqlStatements []string) {
	sqlStatements = append(sqlStatements, generateViewAllLogs(tables))
	// add future views here
	return
}

// generateViewAllLogs creates a view over all log sources using "panther" fields
func generateViewAllLogs(tables []*awsglue.GlueMetadata) (sql string) {
	columns := gluecf.InferJSONColumns(parsers.PantherLog{}, gluecf.GlueMappings...)
	var selectColumns []string
	for _, col := range columns {
		selectColumns = append(selectColumns, col.Name)
	}
	selectClause := strings.Join(selectColumns, ",") + ",year,month,day,hour"

	var sqlLines []string
	sqlLines = append(sqlLines, fmt.Sprintf("create or replace view %s.all_logs as", awsglue.ViewsDatabaseName))

	for i, table := range tables {
		sqlLines = append(sqlLines, fmt.Sprintf("select %s from %s.%s",
			selectClause, table.DatabaseName(), table.TableName()))
		if i < len(tables)-1 {
			sqlLines = append(sqlLines, fmt.Sprintf("\n\tunion all"))
		}
	}

	sqlLines = append(sqlLines, fmt.Sprintf(";\n"))
	sql = strings.Join(sqlLines, "\n")
	return
}
