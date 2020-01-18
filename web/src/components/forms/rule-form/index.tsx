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

import React from 'react';
import { RuleDetails, PolicyUnitTest } from 'Generated/schema';
import * as Yup from 'yup';
import { Box } from 'pouncejs';
import ErrorBoundary from 'Components/error-boundary';
import BaseRuleForm, { BaseRuleFormProps } from 'Components/forms/common/base-rule-form';
import RuleFormCoreFields, { ruleCoreEditableFields } from '../common/rule-form-core-fields';
import RuleFormTestFields from '../common/rule-form-test-fields';

export const ruleEditableFields = [...ruleCoreEditableFields, 'logTypes', 'tests'] as const;

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

export type RuleFormValues = Pick<RuleDetails, typeof ruleEditableFields[number]>;
export type RuleFormProps = Pick<BaseRuleFormProps<RuleFormValues>, 'initialValues' | 'onSubmit'>;

const RuleForm: React.FC<RuleFormProps> = ({ initialValues, onSubmit }) => {
  return (
    <BaseRuleForm<RuleFormValues>
      initialValues={initialValues}
      onSubmit={onSubmit}
      validationSchema={validationSchema}
    >
      <Box is="article">
        <ErrorBoundary>
          <RuleFormCoreFields type="rule" />
        </ErrorBoundary>
        <ErrorBoundary>
          <RuleFormTestFields />
        </ErrorBoundary>
      </Box>
    </BaseRuleForm>
  );
};

export default RuleForm;
