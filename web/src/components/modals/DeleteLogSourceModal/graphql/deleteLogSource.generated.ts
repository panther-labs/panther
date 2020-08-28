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

export type DeleteLogSourceVariables = {
  id: Types.Scalars['ID'];
};

export type DeleteLogSource = Pick<Types.Mutation, 'deleteLogIntegration'>;

export const DeleteLogSourceDocument = gql`
  mutation DeleteLogSource($id: ID!) {
    deleteLogIntegration(id: $id)
  }
`;
export type DeleteLogSourceMutationFn = ApolloReactCommon.MutationFunction<
  DeleteLogSource,
  DeleteLogSourceVariables
>;

/**
 * __useDeleteLogSource__
 *
 * To run a mutation, you first call `useDeleteLogSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteLogSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteLogSource, { data, loading, error }] = useDeleteLogSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useDeleteLogSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteLogSource, DeleteLogSourceVariables>
) {
  return ApolloReactHooks.useMutation<DeleteLogSource, DeleteLogSourceVariables>(
    DeleteLogSourceDocument,
    baseOptions
  );
}
export type DeleteLogSourceHookResult = ReturnType<typeof useDeleteLogSource>;
export type DeleteLogSourceMutationResult = ApolloReactCommon.MutationResult<DeleteLogSource>;
export type DeleteLogSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteLogSource,
  DeleteLogSourceVariables
>;
export function mockDeleteLogSource({
  data,
  variables,
  errors,
}: {
  data: DeleteLogSource;
  variables?: DeleteLogSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: DeleteLogSourceDocument, variables },
    result: { data, errors },
  };
}
