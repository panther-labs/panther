/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import * as Types from '../../../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteRuleVariables = {
  input: Types.DeleteRuleInput;
};

export type DeleteRule = Pick<Types.Mutation, 'deleteRule'>;

export const DeleteRuleDocument = gql`
  mutation DeleteRule($input: DeleteRuleInput!) {
    deleteRule(input: $input)
  }
`;
export type DeleteRuleMutationFn = ApolloReactCommon.MutationFunction<
  DeleteRule,
  DeleteRuleVariables
>;

/**
 * __useDeleteRule__
 *
 * To run a mutation, you first call `useDeleteRule` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteRule` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteRule, { data, loading, error }] = useDeleteRule({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useDeleteRule(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteRule, DeleteRuleVariables>
) {
  return ApolloReactHooks.useMutation<DeleteRule, DeleteRuleVariables>(
    DeleteRuleDocument,
    baseOptions
  );
}
export type DeleteRuleHookResult = ReturnType<typeof useDeleteRule>;
export type DeleteRuleMutationResult = ApolloReactCommon.MutationResult<DeleteRule>;
export type DeleteRuleMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteRule,
  DeleteRuleVariables
>;
export function mockDeleteRule({
  data,
  variables,
  errors,
}: {
  data: DeleteRule;
  variables?: DeleteRuleVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: DeleteRuleDocument, variables },
    result: { data, errors },
  };
}
