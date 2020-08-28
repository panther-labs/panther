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

export type DeleteGlobalPythonModuleVariables = {
  input: Types.DeleteGlobalPythonModuleInput;
};

export type DeleteGlobalPythonModule = Pick<Types.Mutation, 'deleteGlobalPythonModule'>;

export const DeleteGlobalPythonModuleDocument = gql`
  mutation DeleteGlobalPythonModule($input: DeleteGlobalPythonModuleInput!) {
    deleteGlobalPythonModule(input: $input)
  }
`;
export type DeleteGlobalPythonModuleMutationFn = ApolloReactCommon.MutationFunction<
  DeleteGlobalPythonModule,
  DeleteGlobalPythonModuleVariables
>;

/**
 * __useDeleteGlobalPythonModule__
 *
 * To run a mutation, you first call `useDeleteGlobalPythonModule` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteGlobalPythonModule` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteGlobalPythonModule, { data, loading, error }] = useDeleteGlobalPythonModule({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useDeleteGlobalPythonModule(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    DeleteGlobalPythonModule,
    DeleteGlobalPythonModuleVariables
  >
) {
  return ApolloReactHooks.useMutation<DeleteGlobalPythonModule, DeleteGlobalPythonModuleVariables>(
    DeleteGlobalPythonModuleDocument,
    baseOptions
  );
}
export type DeleteGlobalPythonModuleHookResult = ReturnType<typeof useDeleteGlobalPythonModule>;
export type DeleteGlobalPythonModuleMutationResult = ApolloReactCommon.MutationResult<
  DeleteGlobalPythonModule
>;
export type DeleteGlobalPythonModuleMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteGlobalPythonModule,
  DeleteGlobalPythonModuleVariables
>;
export function mockDeleteGlobalPythonModule({
  data,
  variables,
  errors,
}: {
  data: DeleteGlobalPythonModule;
  variables?: DeleteGlobalPythonModuleVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: DeleteGlobalPythonModuleDocument, variables },
    result: { data, errors },
  };
}
