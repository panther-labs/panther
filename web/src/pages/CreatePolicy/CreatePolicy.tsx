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
import Panel from 'Components/Panel';
import { Alert, Box } from 'pouncejs';
import urls from 'Source/urls';
import PolicyForm from 'Components/forms/PolicyForm';
import { PolicyDetails } from 'Generated/schema';
import { DEFAULT_POLICY_FUNCTION } from 'Source/constants';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { extractErrorMessage } from 'Helpers/utils';
import { ListPoliciesDocument } from 'Pages/ListPolicies';
import useRouter from 'Hooks/useRouter';
import { useCreatePolicy } from './graphql/createPolicy.generated';

export const initialValues: PolicyDetails = {
  autoRemediationId: '',
  autoRemediationParameters: '{}',
  description: '',
  displayName: '',
  enabled: true,
  suppressions: [],
  id: '',
  reference: '',
  resourceTypes: [],
  runbook: '',
  severity: null,
  tags: [],
  body: DEFAULT_POLICY_FUNCTION,
  tests: [],
};

const CreatePolicyPage: React.FC = () => {
  const { history } = useRouter();
  const [createPolicy, { error }] = useCreatePolicy({
    refetchQueries: [getOperationName(ListPoliciesDocument)],
    onCompleted: data => history.push(urls.compliance.policies.details(data.addPolicy.id)),
  });

  const handleSubmit = React.useCallback(
    values => createPolicy({ variables: { input: values } }),
    []
  );

  return (
    <Box mb={6}>
      <Panel size="large" title="Policy Settings">
        <PolicyForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {error && (
        <Alert
          mt={2}
          mb={6}
          variant="error"
          title={
            extractErrorMessage(error) ||
            'An unknown error occured as we were trying to create your policy'
          }
        />
      )}
    </Box>
  );
};

export default CreatePolicyPage;
