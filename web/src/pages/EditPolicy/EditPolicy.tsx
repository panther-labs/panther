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
import Panel from 'Components/Panel';
import { Alert, Button, Card, Box, useSnackbar } from 'pouncejs';
import PolicyForm, { policyEditableFields } from 'Components/forms/PolicyForm';
import { PolicyDetails } from 'Generated/schema';
import { initialValues as createPolicyInitialValues } from 'Pages/CreatePolicy';
import useModal from 'Hooks/useModal';
import useRouter from 'Hooks/useRouter';
import TablePlaceholder from 'Components/TablePlaceholder';
import { MODALS } from 'Components/utils/Modal';
import pick from 'lodash-es/pick';
import { extractErrorMessage, formatJSON } from 'Helpers/utils';
import { usePolicyDetails } from './graphql/policyDetails.generated';
import { useUpdatePolicy } from './graphql/updatePolicy.generated';

const EditPolicyPage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { showModal } = useModal();
  const { pushSnackbar } = useSnackbar();

  const { error: fetchPolicyError, data: queryData, loading: isFetchingPolicy } = usePolicyDetails({
    variables: {
      input: {
        policyId: match.params.id,
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

  const initialValues = React.useMemo(() => {
    if (queryData) {
      const { tests, autoRemediationParameters, ...otherInitialValues } = pick(
        queryData.policy,
        policyEditableFields
      ) as PolicyDetails;

      // format any JSON returned from the server simply because we are going to display it
      // within an online web editor. To do that we parse the JSON and re-stringify it using proper
      // spacings that make it pretty (The server of course doesn't store these spacings when
      // it stores JSON, that's why we are making those here in the front-end)
      return {
        ...otherInitialValues,
        autoRemediationParameters: formatJSON(JSON.parse(autoRemediationParameters)),
        tests: tests.map(({ resource, ...restTestData }) => ({
          ...restTestData,
          resource: formatJSON(JSON.parse(resource)),
        })),
      };
    }

    return createPolicyInitialValues;
  }, [queryData]);

  if (isFetchingPolicy) {
    return (
      <Card p={9}>
        <TablePlaceholder rowCount={5} rowHeight={15} />
        <TablePlaceholder rowCount={1} rowHeight={100} />
      </Card>
    );
  }

  if (fetchPolicyError) {
    return (
      <Alert
        mb={6}
        variant="error"
        title="Couldn't load the policy details"
        description={
          extractErrorMessage(fetchPolicyError) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  return (
    <Box mb={6}>
      <Panel
        size="large"
        title="Policy Settings"
        actions={
          <Button
            variant="default"
            size="large"
            color="red300"
            onClick={() =>
              showModal({
                modal: MODALS.DELETE_POLICY,
                props: { policy: queryData.policy },
              })
            }
          >
            Delete
          </Button>
        }
      >
        <PolicyForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {updateError && (
        <Alert
          mt={2}
          mb={6}
          variant="error"
          title={
            extractErrorMessage(updateError) ||
            'Unknown error occured during update. Please contact support@runpanther.io'
          }
        />
      )}
    </Box>
  );
};

export default EditPolicyPage;
