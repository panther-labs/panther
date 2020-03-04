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
import { Alert, Button, Card, Box } from 'pouncejs';
import RuleForm from 'Components/forms/rule-form';
import { GetRuleInput, RuleDetails } from 'Generated/schema';
import useModal from 'Hooks/useModal';
import { useMutation, useQuery, gql } from '@apollo/client';
import useRouter from 'Hooks/useRouter';
import TablePlaceholder from 'Components/TablePlaceholder';
import { MODALS } from 'Components/utils/modal-context';
import useEditRule from 'Hooks/useEditRule';
import { extractErrorMessage } from 'Helpers/utils';

const RULE_DETAILS = gql`
  query RuleDetails($input: GetRuleInput!) {
    rule(input: $input) {
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

const UPDATE_RULE = gql`
  mutation UpdateRule($input: CreateOrModifyRuleInput!) {
    updateRule(input: $input) {
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

interface ApolloQueryData {
  rule: RuleDetails;
}

interface ApolloQueryInput {
  input: GetRuleInput;
}

interface ApolloMutationData {
  updateRule: RuleDetails;
}

interface ApolloMutationInput {
  input: GetRuleInput;
}

const EditRulePage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { showModal } = useModal();

  const { error: fetchRuleError, data: queryData, loading: isFetchingRule } = useQuery<
    ApolloQueryData,
    ApolloQueryInput
  >(RULE_DETAILS, {
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        ruleId: match.params.id,
      },
    },
  });

  const mutation = useMutation<ApolloMutationData, ApolloMutationInput>(UPDATE_RULE);

  const { initialValues, handleSubmit, error: updateError } = useEditRule<ApolloMutationData>({
    mutation,
    type: 'rule',
    rule: queryData?.rule,
  });

  if (isFetchingRule) {
    return (
      <Card p={9}>
        <TablePlaceholder rowCount={5} rowHeight={15} />
        <TablePlaceholder rowCount={1} rowHeight={100} />
      </Card>
    );
  }

  if (fetchRuleError) {
    return (
      <Alert
        mb={6}
        variant="error"
        title="Couldn't load the rule details"
        description={
          extractErrorMessage(fetchRuleError) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  return (
    <Box mb={10}>
      <Panel
        size="large"
        title="Rule Settings"
        actions={
          <Button
            variant="default"
            size="large"
            color="red300"
            onClick={() =>
              showModal({
                modal: MODALS.DELETE_RULE,
                props: { rule: queryData.rule },
              })
            }
          >
            Delete
          </Button>
        }
      >
        <RuleForm initialValues={initialValues} onSubmit={handleSubmit} />
      </Panel>
      {updateError && (
        <Alert
          mt={2}
          mb={6}
          variant="error"
          title={
            extractErrorMessage(updateError) ||
            'An unknown error occured as were trying to update your rule'
          }
        />
      )}
    </Box>
  );
};

export default EditRulePage;
