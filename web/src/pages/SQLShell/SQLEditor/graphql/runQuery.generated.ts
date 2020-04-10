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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type RunQueryVariables = {
  input: Types.ExecuteAsyncLogQueryInput;
};

export type RunQuery = { executeAsyncLogQuery: Pick<Types.ExecuteAsyncLogQueryOutput, 'queryId'> };

export const RunQueryDocument = gql`
  mutation RunQuery($input: executeAsyncLogQueryInput!) {
    executeAsyncLogQuery(input: $input) {
      queryId
    }
  }
`;
export type RunQueryMutationFn = ApolloReactCommon.MutationFunction<RunQuery, RunQueryVariables>;

/**
 * __useRunQuery__
 *
 * To run a mutation, you first call `useRunQuery` within a React component and pass it any options that fit your needs.
 * When your component renders, `useRunQuery` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [runQuery, { data, loading, error }] = useRunQuery({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useRunQuery(
  baseOptions?: ApolloReactHooks.MutationHookOptions<RunQuery, RunQueryVariables>
) {
  return ApolloReactHooks.useMutation<RunQuery, RunQueryVariables>(RunQueryDocument, baseOptions);
}
export type RunQueryHookResult = ReturnType<typeof useRunQuery>;
export type RunQueryMutationResult = ApolloReactCommon.MutationResult<RunQuery>;
export type RunQueryMutationOptions = ApolloReactCommon.BaseMutationOptions<
  RunQuery,
  RunQueryVariables
>;
