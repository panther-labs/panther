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
import PolicyForm from 'Components/forms/PolicyForm';
import useRouter from 'Hooks/useRouter';
import withSEO from 'Hoc/withSEO';
import { extractErrorMessage, formatJSON } from 'Helpers/utils';
import { useGetPolicyDetails } from './graphql/getPolicyDetails.generated';
import { useUpdatePolicy } from './graphql/updatePolicy.generated';
import Skeleton from './Skeleton';

const EditPolicyPage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { pushSnackbar } = useSnackbar();

  const {
    error: fetchPolicyError,
    data: queryData,
    loading: isFetchingPolicy,
  } = useGetPolicyDetails({
    variables: {
      input: {
        id: match.params.id,
      },
    },
  });

  const [updatePolicy, { error: updateError }] = useUpdatePolicy({
    onCompleted: () =>
      pushSnackbar({
        variant: 'success',
        title: 'Successfully updated policy!',
      }),
  });

  const handleSubmit = React.useCallback(
    values => updatePolicy({ variables: { input: values } }),
    []
  );

  if (isFetchingPolicy) {
    return <Skeleton />;
  }

  if (fetchPolicyError) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load the policy details"
          discardable
          description={
            extractErrorMessage(fetchPolicyError) ||
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
  const { policy } = queryData;
  const initialValues = {
    autoRemediationId: policy.autoRemediationId,
    autoRemediationParameters: formatJSON(JSON.parse(policy.autoRemediationParameters)),
    body: policy.body,
    description: policy.description,
    displayName: policy.displayName,
    enabled: policy.enabled,
    id: policy.id,
    outputIds: policy.outputIds,
    reference: policy.reference,
    resourceTypes: policy.resourceTypes,
    runbook: policy.runbook,
    severity: policy.severity,
    suppressions: policy.suppressions,
    tags: policy.tags,
    tests: queryData.policy.tests.map(({ resource, ...restTestData }) => ({
      ...restTestData,
      resource: formatJSON(JSON.parse(resource)),
    })),
  };

  return (
    <Box mb={6}>
      <PolicyForm initialValues={initialValues} onSubmit={handleSubmit} />
      {updateError && (
        <Box mt={2} mb={6}>
          <Alert
            variant="error"
            title="Couldn't update your policy"
            description={
              extractErrorMessage(updateError) ||
              'Unknown error occured during update. Please contact support@runpanther.io'
            }
          />
        </Box>
      )}
    </Box>
  );
};

export default withSEO({ title: ({ match }) => `Edit ${match.params.id}` })(EditPolicyPage);
