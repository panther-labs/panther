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
import PolicyForm from 'Components/Forms/PolicyForm';
import { GetPolicyInput, PolicyDetails, ResourceDetails } from 'Generated/schema';
import { useMutation, gql } from '@apollo/client';
import { DEFAULT_POLICY_FUNCTION } from 'Source/constants';
import useCreateRule from 'Hooks/useCreateRule';
import { LIST_POLICIES } from 'Pages/list-policies';
import { getOperationName } from '@apollo/client/utilities/graphql/getFromAST';
import { extractErrorMessage } from 'Helpers/utils';

const initialValues: PolicyDetails = {
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

const CREATE_POLICY = gql`
  mutation CreatePolicy($input: CreateOrModifyPolicyInput!) {
    addPolicy(input: $input) {
      autoRemediationId
      autoRemediationParameters
      description
      displayName
      enabled
      suppressions
      id
      reference
      resourceTypes
      runbook
      severity
      tags
      body
      tests {
        expectedResult
        name
        resource
        resourceType
      }
    }
  }
`;

interface ApolloMutationData {
  addPolicy: ResourceDetails;
}

interface ApolloMutationInput {
  input: GetPolicyInput;
}

const EditPolicyPage: React.FC = () => {
  const mutation = useMutation<ApolloMutationData, ApolloMutationInput>(CREATE_POLICY, {
    refetchQueries: [getOperationName(LIST_POLICIES)],
  });

  const { handleSubmit, error } = useCreateRule<ApolloMutationData>({
    mutation,
    getRedirectUri: data => urls.compliance.policies.details(data.addPolicy.id),
  });

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

export default EditPolicyPage;
