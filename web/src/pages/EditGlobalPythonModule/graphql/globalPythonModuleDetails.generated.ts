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

export type GlobalPythonModuleDetailsVariables = {
  input: Types.GetGlobalPythonModuleInput;
};

export type GlobalPythonModuleDetails = { getGlobalPythonModule: GlobalPythonModuleFull };

export const GlobalPythonModuleDetailsDocument = gql`
  query GlobalPythonModuleDetails($input: GetGlobalPythonModuleInput!) {
    getGlobalPythonModule(input: $input) {
      ...GlobalPythonModuleFull
    }
  }
  ${GlobalPythonModuleFull}
`;

/**
 * __useGlobalPythonModuleDetails__
 *
 * To run a query within a React component, call `useGlobalPythonModuleDetails` and pass it any options that fit your needs.
 * When your component renders, `useGlobalPythonModuleDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGlobalPythonModuleDetails({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGlobalPythonModuleDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GlobalPythonModuleDetails,
    GlobalPythonModuleDetailsVariables
  >
) {
  return ApolloReactHooks.useQuery<GlobalPythonModuleDetails, GlobalPythonModuleDetailsVariables>(
    GlobalPythonModuleDetailsDocument,
    baseOptions
  );
}
export function useGlobalPythonModuleDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GlobalPythonModuleDetails,
    GlobalPythonModuleDetailsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<
    GlobalPythonModuleDetails,
    GlobalPythonModuleDetailsVariables
  >(GlobalPythonModuleDetailsDocument, baseOptions);
}
export type GlobalPythonModuleDetailsHookResult = ReturnType<typeof useGlobalPythonModuleDetails>;
export type GlobalPythonModuleDetailsLazyQueryHookResult = ReturnType<
  typeof useGlobalPythonModuleDetailsLazyQuery
>;
export type GlobalPythonModuleDetailsQueryResult = ApolloReactCommon.QueryResult<
  GlobalPythonModuleDetails,
  GlobalPythonModuleDetailsVariables
>;
export function mockGlobalPythonModuleDetails({
  data,
  variables,
  errors,
}: {
  data: GlobalPythonModuleDetails;
  variables?: GlobalPythonModuleDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GlobalPythonModuleDetailsDocument, variables },
    result: { data, errors },
  };
}
