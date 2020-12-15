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

import * as Types from '../../../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteCustomLogVariables = {
  input: Types.DeleteCustomLogInput;
};

export type DeleteCustomLog = {
  deleteCustomLog: { error?: Types.Maybe<Pick<Types.Error, 'message'>> };
};

export const DeleteCustomLogDocument = gql`
  mutation DeleteCustomLog($input: DeleteCustomLogInput!) {
    deleteCustomLog(input: $input) {
      error {
        message
      }
    }
  }
`;
export type DeleteCustomLogMutationFn = ApolloReactCommon.MutationFunction<
  DeleteCustomLog,
  DeleteCustomLogVariables
>;

/**
 * __useDeleteCustomLog__
 *
 * To run a mutation, you first call `useDeleteCustomLog` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteCustomLog` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteCustomLog, { data, loading, error }] = useDeleteCustomLog({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useDeleteCustomLog(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteCustomLog, DeleteCustomLogVariables>
) {
  return ApolloReactHooks.useMutation<DeleteCustomLog, DeleteCustomLogVariables>(
    DeleteCustomLogDocument,
    baseOptions
  );
}
export type DeleteCustomLogHookResult = ReturnType<typeof useDeleteCustomLog>;
export type DeleteCustomLogMutationResult = ApolloReactCommon.MutationResult<DeleteCustomLog>;
export type DeleteCustomLogMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteCustomLog,
  DeleteCustomLogVariables
>;
export function mockDeleteCustomLog({
  data,
  variables,
  errors,
}: {
  data: DeleteCustomLog;
  variables?: DeleteCustomLogVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: DeleteCustomLogDocument, variables },
    result: { data, errors },
  };
}
