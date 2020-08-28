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

import * as Types from '../../../../__generated__/schema';

import { GlobalPythonModuleFull } from '../../../graphql/fragments/GlobalPythonModuleFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type CreateGlobalPythonModuleVariables = {
  input: Types.AddGlobalPythonModuleInput;
};

export type CreateGlobalPythonModule = { addGlobalPythonModule: GlobalPythonModuleFull };

export const CreateGlobalPythonModuleDocument = gql`
  mutation CreateGlobalPythonModule($input: AddGlobalPythonModuleInput!) {
    addGlobalPythonModule(input: $input) {
      ...GlobalPythonModuleFull
    }
  }
  ${GlobalPythonModuleFull}
`;
export type CreateGlobalPythonModuleMutationFn = ApolloReactCommon.MutationFunction<
  CreateGlobalPythonModule,
  CreateGlobalPythonModuleVariables
>;

/**
 * __useCreateGlobalPythonModule__
 *
 * To run a mutation, you first call `useCreateGlobalPythonModule` within a React component and pass it any options that fit your needs.
 * When your component renders, `useCreateGlobalPythonModule` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [createGlobalPythonModule, { data, loading, error }] = useCreateGlobalPythonModule({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useCreateGlobalPythonModule(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    CreateGlobalPythonModule,
    CreateGlobalPythonModuleVariables
  >
) {
  return ApolloReactHooks.useMutation<CreateGlobalPythonModule, CreateGlobalPythonModuleVariables>(
    CreateGlobalPythonModuleDocument,
    baseOptions
  );
}
export type CreateGlobalPythonModuleHookResult = ReturnType<typeof useCreateGlobalPythonModule>;
export type CreateGlobalPythonModuleMutationResult = ApolloReactCommon.MutationResult<
  CreateGlobalPythonModule
>;
export type CreateGlobalPythonModuleMutationOptions = ApolloReactCommon.BaseMutationOptions<
  CreateGlobalPythonModule,
  CreateGlobalPythonModuleVariables
>;
export function mockCreateGlobalPythonModule({
  data,
  variables,
  errors,
}: {
  data: CreateGlobalPythonModule;
  variables?: CreateGlobalPythonModuleVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: CreateGlobalPythonModuleDocument, variables },
    result: { data, errors },
  };
}
