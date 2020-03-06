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
import { MutationTuple } from '@apollo/client';
import pick from 'lodash-es/pick';
import { formatJSON } from 'Helpers/utils';
import { testEditableFields } from 'Components/forms/common/RuleFormTestFields';
import { useSnackbar } from 'pouncejs';
import { PolicyDetails, RuleDetails } from 'Generated/schema';
import { policyEditableFields } from 'Components/forms/PolicyForm';
import { ruleEditableFields } from 'Components/forms/RuleForm';
import { ruleCoreEditableFields } from 'Components/forms/common/RuleFormCoreFields';

interface UseEditRuleProps<T> {
  rule: RuleDetails | PolicyDetails;
  type: 'policy' | 'rule';
  mutation: MutationTuple<T, { [key: string]: any }>;
}

function useEditRule<T>({ mutation, rule, type }: UseEditRuleProps<T>) {
  const { pushSnackbar } = useSnackbar();
  const [editRule, { data, error }] = mutation;

  const isPolicy = type === 'policy';
  const initialValues = React.useMemo(() => {
    if (rule) {
      const pickedFields = isPolicy
        ? (pick(rule, policyEditableFields) as PolicyDetails)
        : (pick(rule, ruleEditableFields) as RuleDetails);

      const { tests, ...otherInitialValues } = pickedFields;

      // format any JSON returned from the server simply because we are going to display it
      // within an online web editor. To do that we parse the JSON and re-stringify it using proper
      // spacings that make it pretty (The server of course doesn't store these spacings when
      // it stores JSON, that's why we are making those here in the front-end)
      return {
        ...(otherInitialValues as Pick<typeof rule, typeof ruleCoreEditableFields[number]>),
        ...(isPolicy && {
          autoRemediationParameters: formatJSON(
            JSON.parse((pickedFields as PolicyDetails).autoRemediationParameters)
          ),
        }),
        tests: tests
          .map(test => pick(test, testEditableFields))
          .map(({ resource, ...restTestData }) => ({
            ...restTestData,
            resource: formatJSON(JSON.parse(resource)),
          })),
      };
    }

    return undefined;
  }, [rule]);

  const handleSubmit = React.useCallback(async values => {
    await editRule({ variables: { input: values } });
  }, []);

  React.useEffect(() => {
    if (data) {
      // After all is ok just inform the user and *don't* redirect
      pushSnackbar({
        variant: 'success',
        title: `Successfully updated ${isPolicy ? 'policy' : 'rule'}!`,
      });
    }
  }, [data]);

  return { handleSubmit, initialValues, data, error };
}

export default useEditRule;
