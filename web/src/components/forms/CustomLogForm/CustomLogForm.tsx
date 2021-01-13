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
import * as Yup from 'yup';
import map from 'lodash/map';
import isEmpty from 'lodash/isEmpty';
import { Card, SimpleGrid, Heading, Flex, Button, Box, Text } from 'pouncejs';
import Breadcrumbs from 'Components/Breadcrumbs';
import { FastField, Formik, Form } from 'formik';
import type { ValidationError } from 'jsonschema';
import type { YAMLException } from 'js-yaml';
import FormikTextInput from 'Components/fields/TextInput';
import FormikEditor from 'Components/fields/Editor';
import SaveButton from 'Components/buttons/SaveButton';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import useRouter from 'Hooks/useRouter';
import ValidateButton from './ValidateButton';

export interface CustomLogFormValues {
  name: string;
  description: string;
  revision?: number;
  referenceUrl: string;
  schema: string;
}

export interface CustomLogFormProps {
  initialValues: CustomLogFormValues;
  onSubmit: (values: CustomLogFormValues) => Promise<any>;
}

export type SchemaErrors = Record<string, (ValidationError | YAMLException)[]>;

const validationSchema = Yup.object({
  name: Yup.string()
    .matches(
      /^Custom\.[A-Z]/,
      'Must start with Custom. (notice the dot) followed by a capital letter. For example: Custom.OSLog'
    )
    .matches(/^Custom\.[A-Z]([A-Za-z0-9]+)$/, 'Can only be followed by alphanumeric characters')
    .required(),
  description: Yup.string(),
  referenceUrl: Yup.string().url(),
  schema: Yup.string().required(),
});

const CustomLogForm: React.FC<CustomLogFormProps> = ({ onSubmit, initialValues }) => {
  const { history } = useRouter();
  const [schemaErrors, setSchemaErrors] = React.useState<SchemaErrors>(null);

  const isSchemaValid = schemaErrors && isEmpty(schemaErrors);
  const hasSchemaErrors = schemaErrors && !isEmpty(schemaErrors);
  const userHasValidatedSyntax = isSchemaValid || hasSchemaErrors;
  const isEditing = initialValues.revision && initialValues.revision > 0;
  return (
    <Formik<CustomLogFormValues>
      enableReinitialize
      initialValues={initialValues}
      onSubmit={onSubmit}
      validationSchema={validationSchema}
    >
      <FormSessionRestoration sessionId={`custom-log-form-${initialValues.revision || 'create'}`}>
        {({ clearFormSession }) => (
          <Form>
            <SimpleGrid columns={3} spacing={5} mb={5}>
              <FastField
                as={FormikTextInput}
                name="name"
                label="* Name"
                placeholder="Must start with `Custom.` followed by a capital letter"
                disabled={isEditing}
                required
              />
              <FastField
                as={FormikTextInput}
                name="description"
                label="Description"
                placeholder="A verbose description of what this log type does"
              />
              <FastField
                as={FormikTextInput}
                name="referenceUrl"
                label="Reference URL"
                placeholder="The URL to the log's schema documentation"
              />
            </SimpleGrid>
            <Card variant="dark" px={4} py={5} mb={5} as="section">
              <Heading size="x-small" mb={5}>
                Event Schema
              </Heading>
              <FastField
                as={FormikEditor}
                placeholder="# Write your schema in YAML here..."
                name="schema"
                width="100%"
                minLines={16}
                mode="yaml"
                aria-labelledby={hasSchemaErrors ? 'schema-errors' : undefined}
                required
              />
            </Card>
            {isSchemaValid && (
              <Box
                my={5}
                p={4}
                borderRadius="medium"
                backgroundColor="green-500"
                fontSize="medium"
                fontWeight="bold"
              >
                Everything{"'"}s looking good
              </Box>
            )}
            {hasSchemaErrors && (
              <Box
                my={5}
                p={4}
                borderRadius="medium"
                backgroundColor="pink-700"
                fontSize="medium"
                id="schema-errors"
              >
                <Flex direction="column" spacing={2}>
                  {map(schemaErrors, (errors, fieldName) => (
                    <Box key={fieldName}>
                      <Box as="b">{fieldName}</Box>
                      {errors.map((err, index) => (
                        <Text key={index} fontStyle="italic" ml={4}>
                          {err.message}
                        </Text>
                      ))}
                    </Box>
                  ))}
                </Flex>
              </Box>
            )}
            <ValidateButton setSchemaErrors={setSchemaErrors}>
              {!userHasValidatedSyntax ? 'Validate Syntax' : 'Validate Again'}
            </ValidateButton>
            <Breadcrumbs.Actions>
              <Flex justify="flex-end" spacing={4}>
                <SaveButton>{isEditing ? 'Update' : 'Save'} log</SaveButton>
                <Button
                  variantColor="darkgray"
                  icon="close-outline"
                  onClick={() => {
                    clearFormSession();
                    history.goBack();
                  }}
                >
                  Cancel
                </Button>
              </Flex>
            </Breadcrumbs.Actions>
          </Form>
        )}
      </FormSessionRestoration>
    </Formik>
  );
};

export default CustomLogForm;
