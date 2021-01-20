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
import { Alert, Box, useSnackbar } from 'pouncejs';
import RuleForm from 'Components/forms/RuleForm';
import useRouter from 'Hooks/useRouter';
import { extractErrorMessage, formatJSON } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import Skeleton from './Skeleton';
import { useGetRuleDetails } from './graphql/getRuleDetails.generated';
import { useUpdateRule } from './graphql/updateRule.generated';

const EditRulePage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { pushSnackbar } = useSnackbar();

  const { error: fetchRuleError, data: queryData, loading: isFetchingRule } = useGetRuleDetails({
    variables: {
      input: {
        id: match.params.id,
      },
    },
  });

  const [updateRule, { error: updateError }] = useUpdateRule({
    onCompleted: () =>
      pushSnackbar({
        variant: 'success',
        title: 'Successfully updated rule!',
      }),
  });

  const handleSubmit = React.useCallback(
    values => updateRule({ variables: { input: values } }),
    []
  );

  if (isFetchingRule) {
    return <Skeleton />;
  }

  if (fetchRuleError) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load the rule details"
          description={
            extractErrorMessage(fetchRuleError) ||
            'There was an error when performing your request, please contact support@runpanther.io'
          }
        />
      </Box>
    );
  }

  // format any JSON returned from the server simply because we are going to display it
  // within an online web editor. To do that we parse the JSON and re-stringify it using proper
  // spacings that make it pretty (The server of course doesn't store these spacings when
  // it stores JSON, that's why we are making those here in the front-end)
  const { rule } = queryData;
  const initialValues = {
    body: rule.body,
    dedupPeriodMinutes: rule.dedupPeriodMinutes,
    threshold: rule.threshold,
    description: rule.description,
    displayName: rule.displayName,
    enabled: rule.enabled,
    id: rule.id,
    logTypes: rule.logTypes,
    outputIds: rule.outputIds,
    reference: rule.reference,
    runbook: rule.runbook,
    severity: rule.severity,
    tags: rule.tags,
    tests: rule.tests.map(({ resource, ...restTestData }) => ({
      ...restTestData,
      resource: formatJSON(JSON.parse(resource)),
    })),
  };

  return (
    <Box mb={6}>
      <RuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      {updateError && (
        <Box mt={2} mb={6}>
          <Alert
            variant="error"
            discardable
            title={
              extractErrorMessage(updateError) ||
              'An unknown error occured as were trying to update your rule'
            }
          />
        </Box>
      )}
    </Box>
  );
};

export default withSEO({ title: ({ match }) => `Edit ${match.params.id}` })(EditRulePage);
