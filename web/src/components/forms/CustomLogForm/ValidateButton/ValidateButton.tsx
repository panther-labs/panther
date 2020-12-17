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

import React from 'react';
import { Button } from 'pouncejs';
import { useFormikContext } from 'formik';
import groupBy from 'lodash/groupBy';
import type { YAMLException } from 'js-yaml';
import schemaBlueprint from 'Public/schemas/customlogs_v0_schema.json';
import { CustomLogFormValues, SchemaErrors } from '../CustomLogForm';

interface ValidateButtonProps {
  setSchemaErrors: (errors: SchemaErrors) => void;
}

const ValidateButton: React.FC<ValidateButtonProps> = ({ setSchemaErrors, children }) => {
  const { values: { schema } } = useFormikContext<CustomLogFormValues>(); // prettier-ignore

  const handleClick = React.useCallback(async () => {
    import(/* webpackChunkName: "json-schema-validation" */ 'jsonschema').then(({ Validator }) => {
      import(/* webpackChunkName: "json-schema-validation" */ 'js-yaml').then(
        ({ default: yaml }) => {
          try {
            const validator = new Validator();
            const schemaAsObject = yaml.load(schema);
            const result = validator.validate(schemaAsObject, schemaBlueprint as any, {
              propertyName: 'root',
            });

            if (!result.errors.length) {
              setSchemaErrors({});
            } else {
              // Removes un-necessary errors that are bloating the UI
              const withoutSchemaAllOfErrors = result.errors.filter(err => err.name !== 'allOf');

              // Group errors by their associated field
              const errorsByField = groupBy(withoutSchemaAllOfErrors, err => err.property);
              setSchemaErrors(errorsByField);
            }
          } catch (err) {
            const yamlError = err as YAMLException;
            setSchemaErrors({
              [yamlError.name]: [{ name: yamlError.name, message: yamlError.message }],
            });
          }
        }
      );
    });
  }, [schema, setSchemaErrors]);

  return (
    <Button variantColor="teal" icon="play" disabled={!schema} onClick={handleClick}>
      {children}
    </Button>
  );
};

export default ValidateButton;
