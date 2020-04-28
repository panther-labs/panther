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
import { PolicyDetails, PolicyUnitTest } from 'Generated/schema';
import * as Yup from 'yup';
import { Box, Heading } from 'pouncejs';
import BaseRuleForm, {
  BaseRuleFormProps,
  BaseRuleFormTestFields as PolicyFormTestFields,
  BaseRuleFormCoreFields,
  ruleCoreEditableFields,
} from 'Components/forms/BaseRuleForm';
import ErrorBoundary from 'Components/ErrorBoundary';
import PolicyFormAutoRemediationFields from './PolicyFormAutoRemediationFields';

export const policyEditableFields = [
  ...ruleCoreEditableFields,
  'autoRemediationId',
  'autoRemediationParameters',
  'suppressions',
  'resourceTypes',
  'tests',
] as const;

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

export type PolicyFormValues = Pick<PolicyDetails, typeof policyEditableFields[number]>;
export type PolicyFormProps = Pick<
  BaseRuleFormProps<PolicyFormValues>,
  'initialValues' | 'onSubmit'
>;

const PolicyForm: React.FC<PolicyFormProps> = ({ initialValues, onSubmit }) => {
  return (
    <BaseRuleForm<PolicyFormValues>
      initialValues={initialValues}
      onSubmit={onSubmit}
      validationSchema={validationSchema}
    >
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
    </BaseRuleForm>
  );
};

export default PolicyForm;
