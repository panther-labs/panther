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
import { GlobalPythonModule } from 'Generated/schema';
import * as Yup from 'yup';
import { Box, Button, Flex, Grid, InputElementLabel, Text } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Field, Form, Formik } from 'formik';
import SubmitButton from 'Components/buttons/SubmitButton/SubmitButton';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import useRouter from 'Hooks/useRouter';
import FormikTextInput from 'Components/fields/TextInput';
import FormikTextArea from 'Components/fields/TextArea';
import FormikEditor from 'Components/fields/Editor';

// The validation checks that Formik will run
const validationSchema = Yup.object().shape({
  id: Yup.string().required(),
  body: Yup.string().required(),
  description: Yup.string().required(),
});

const globalModuleEditableFields = ['id', 'body', 'description'] as const;

type GlobalModuleFormValues = Pick<GlobalPythonModule, typeof globalModuleEditableFields[number]>;

interface GlobalModuleFormProps {
  /** The initial values of the form */
  initialValues: GlobalModuleFormValues;
  /** callback for the submission of the form */
  onSubmit: (values: GlobalModuleFormValues) => void;
}

const GlobalModuleForm: React.FC<GlobalModuleFormProps> = ({ initialValues, onSubmit }) => {
  const { history } = useRouter();

  return (
    <Box as="article">
      <ErrorBoundary>
        <Formik<GlobalModuleFormValues>
          initialValues={initialValues}
          onSubmit={onSubmit}
          enableReinitialize
          validationSchema={validationSchema}
        >
          <FormSessionRestoration sessionId={`global-module-${initialValues.id || 'create'}`}>
            <Form>
              <Text size="large" color="grey300" mb={4}>
                The global module allows you to define a set of reusable functions, variables and
                classes which can be directly imported to your Rule or Policy definition. Anything
                defined below can later be imported through the `panther` module
              </Text>
              <Grid gridTemplateColumns="1fr 1fr" gridRowGap={2} gridColumnGap={9}>
                <Field
                  as={FormikTextInput}
                  label="* ID"
                  placeholder={`The unique ID of the global`}
                  name="id"
                  disabled={initialValues.id}
                  aria-required
                />
                <Field
                  as={FormikTextArea}
                  label="Description"
                  placeholder={`Additional context about this global module`}
                  name="description"
                />
              </Grid>
              <Box my={6}>
                <InputElementLabel htmlFor="enabled">{'Module definitions'}</InputElementLabel>
                <Field
                  as={FormikEditor}
                  placeholder="# Enter the body of the global here..."
                  name="body"
                  width="100%"
                  minLines={16}
                  mode="python"
                  aria-required
                />
              </Box>
              <Flex borderTop="1px solid" borderColor="grey100" pt={6} mt={10} justify="flex-end">
                <Flex>
                  <Button variant="default" size="large" onClick={history.goBack} mr={4}>
                    Cancel
                  </Button>
                  <SubmitButton>{initialValues.id ? 'Update' : 'Create'}</SubmitButton>
                </Flex>
              </Flex>
            </Form>
          </FormSessionRestoration>
        </Formik>
      </ErrorBoundary>
    </Box>
  );
};

export default GlobalModuleForm;
