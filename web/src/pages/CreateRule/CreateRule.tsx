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
import RuleForm from 'Components/forms/RuleForm';
import { GetRuleInput, RuleDetails } from 'Generated/schema';

import { useMutation, gql } from '@apollo/client';
import { DEFAULT_RULE_FUNCTION } from 'Source/constants';
import useCreateRule from 'Hooks/useCreateRule';
import { extractErrorMessage } from 'Helpers/utils';

const initialValues: RuleDetails = {
  description: '',
  displayName: '',
  enabled: true,
  id: '',
  reference: '',
  logTypes: [],
  runbook: '',
  severity: null,
  tags: [],
  body: DEFAULT_RULE_FUNCTION,
  tests: [],
};

const CREATE_RULE = gql`
  mutation CreateRule($input: CreateOrModifyRuleInput!) {
    addRule(input: $input) {
      description
      displayName
      enabled
      id
      reference
      logTypes
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
  addRule: RuleDetails;
}

interface ApolloMutationInput {
  input: GetRuleInput;
}

const CreateRulePage: React.FC = () => {
  const mutation = useMutation<ApolloMutationData, ApolloMutationInput>(CREATE_RULE);

  const { handleSubmit, error } = useCreateRule<ApolloMutationData>({
    mutation,
    getRedirectUri: data => urls.logAnalysis.rules.details(data.addRule.id),
  });

  return (
    <Box mb={10}>
      <Panel size="large" title="Rule Settings">
        <RuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {error && (
        <Alert
          mt={2}
          mb={6}
          variant="error"
          title={
            extractErrorMessage(error) ||
            'An unknown error occured as we were trying to create your rule'
          }
        />
      )}
    </Box>
  );
};

export default CreateRulePage;
