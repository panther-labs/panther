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
import { AddPolicyInput, DetectionTestDefinition, UpdatePolicyInput } from 'Generated/schema';
import * as Yup from 'yup';
import { Button, Flex } from 'pouncejs';
import { Form, Formik } from 'formik';
import SubmitButton from 'Components/buttons/SubmitButton/SubmitButton';
import useRouter from 'Hooks/useRouter';
import { BaseRuleFormCoreSection, BaseRuleFormEditorSection } from 'Components/forms/BaseRuleForm';
import ErrorBoundary from 'Components/ErrorBoundary';
import FormSessionRestoration from 'Components/utils/FormSessionRestoration';
import PolicyFormAutoRemediationSection from './PolicyFormAutoRemediationSection';
import PolicyFormTestSection from './PolicyFormTestSection';

// The validation checks that Formik will run
const validationSchema = Yup.object().shape({
  id: Yup.string().required(),
  body: Yup.string().required(),
  severity: Yup.string().required(),
  tests: Yup.array<DetectionTestDefinition>().of(
    Yup.object().shape({
      name: Yup.string().required(),
      expectedResult: Yup.boolean().required(),
      resource: Yup.string().required(),
    })
  ),
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
        {({ clearFormSession }) => (
          <Form>
            <Flex direction="column" as="article" spacing={5}>
              <ErrorBoundary>
                <BaseRuleFormCoreSection type="policy" />
              </ErrorBoundary>
              <ErrorBoundary>
                <BaseRuleFormEditorSection type="policy" />
              </ErrorBoundary>
              <ErrorBoundary>
                <PolicyFormTestSection />
              </ErrorBoundary>
              <ErrorBoundary>
                <PolicyFormAutoRemediationSection />
              </ErrorBoundary>
            </Flex>
            <Flex spacing={4} mt={5} justify="flex-end">
              <Button
                variant="outline"
                variantColor="navyblue"
                onClick={() => {
                  clearFormSession();
                  history.goBack();
                }}
              >
                Cancel
              </Button>
              <SubmitButton>{initialValues.id ? 'Update' : 'Create'}</SubmitButton>
            </Flex>
          </Form>
        )}
      </FormSessionRestoration>
    </Formik>
  );
};

export default PolicyForm;
