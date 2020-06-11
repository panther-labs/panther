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
import { AddPolicyInput, PolicyUnitTest, UpdatePolicyInput } from 'Generated/schema';
import * as Yup from 'yup';
import { Box, Button, Flex, Heading } from 'pouncejs';
import { Form, Formik } from 'formik';
import SubmitButton from 'Components/buttons/SubmitButton/SubmitButton';
import useRouter from 'Hooks/useRouter';
import {
  BaseRuleFormTestFields as PolicyFormTestFields,
  BaseRuleFormCoreFields,
} from 'Components/forms/BaseRuleForm';
import ErrorBoundary from 'Components/ErrorBoundary';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import PolicyFormAutoRemediationFields from './PolicyFormAutoRemediationFields';

// The validation checks that Formik will run
const validationSchema = Yup.object().shape({
  id: Yup.string().required(),
  body: Yup.string().required(),
  severity: Yup.string().required(),
  tests: Yup.array<PolicyUnitTest>()
    .of(
      Yup.object().shape({
        name: Yup.string().required(),
      })
    )
    .unique('Test names must be unique', 'name'),
});

export type PolicyFormValues = Required<AddPolicyInput> | Required<UpdatePolicyInput>;
export type PolicyFormProps = {
  /** The initial values of the form */
  initialValues: PolicyFormValues;

  /** callback for the submission of the form */
  onSubmit: (values: PolicyFormValues) => void;
};

const PolicyForm: React.FC<PolicyFormProps> = ({ initialValues, onSubmit }) => {
  const { history } = useRouter();

  return (
    <Formik<PolicyFormValues>
      initialValues={initialValues}
      onSubmit={onSubmit}
      enableReinitialize
      validationSchema={validationSchema}
    >
      <FormSessionRestoration sessionId={`policy-form-${initialValues.id || 'create'}`}>
        <Form>
          <Box as="article">
            <ErrorBoundary>
              <BaseRuleFormCoreFields type="policy" />
            </ErrorBoundary>
            <ErrorBoundary>
              <PolicyFormTestFields />
            </ErrorBoundary>
          </Box>
          <Box as="article" mt={10}>
            <Heading size="medium" pb={8} borderBottom="1px solid" borderColor="grey100">
              Auto Remediation Settings
            </Heading>
            <Box mt={8}>
              <ErrorBoundary>
                <PolicyFormAutoRemediationFields />
              </ErrorBoundary>
            </Box>
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

export default PolicyForm;
