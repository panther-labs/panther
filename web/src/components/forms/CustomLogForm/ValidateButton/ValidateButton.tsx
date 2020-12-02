/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
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
