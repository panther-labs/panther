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
import { AddRuleInput, PolicyUnitTest, UpdateRuleInput } from 'Generated/schema';
import * as Yup from 'yup';
import { Box, Button, Flex } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { BaseRuleFormCoreFields, BaseRuleFormTestFields } from 'Components/forms/BaseRuleForm';
import { Form, Formik } from 'formik';
import SubmitButton from 'Components/buttons/SubmitButton/SubmitButton';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import useRouter from 'Hooks/useRouter';

// The validation checks that Formik will run
const validationSchema = Yup.object().shape({
  id: Yup.string().required(),
  body: Yup.string().required(),
  severity: Yup.string().required(),
  dedupPeriodMinutes: Yup.number().integer(),
  logTypes: Yup.array().of(Yup.string()).required(),
  tests: Yup.array<PolicyUnitTest>()
    .of(
      Yup.object().shape({
        name: Yup.string().required(),
      })
    )
    .unique('Test names must be unique', 'name'),
});

export type RuleFormValues = Required<AddRuleInput> | Required<UpdateRuleInput>;
export type RuleFormProps = {
  /** The initial values of the form */
  initialValues: RuleFormValues;

  /** callback for the submission of the form */
  onSubmit: (values: RuleFormValues) => void;
};

const RuleForm: React.FC<RuleFormProps> = ({ initialValues, onSubmit }) => {
  const { history } = useRouter();

  return (
    <Formik<RuleFormValues>
      initialValues={initialValues}
      onSubmit={onSubmit}
      enableReinitialize
      validationSchema={validationSchema}
    >
      <FormSessionRestoration sessionId={`rule-form-${initialValues.id || 'create'}`}>
        <Form>
          <Box as="article">
            <ErrorBoundary>
              <BaseRuleFormCoreFields type="rule" />
            </ErrorBoundary>
            <ErrorBoundary>
              <BaseRuleFormTestFields />
            </ErrorBoundary>
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
  );
};

export default RuleForm;
