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

import { GlobalPythonModuleTeaser } from '../../../graphql/fragments/GlobalPythonModuleTeaser.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListGlobalPythonModulesVariables = {
  input: Types.ListGlobalPythonModuleInput;
};

export type ListGlobalPythonModules = {
  listGlobalPythonModules: {
    globals?: Types.Maybe<Array<Types.Maybe<GlobalPythonModuleTeaser>>>;
    paging?: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
  };
};

export const ListGlobalPythonModulesDocument = gql`
  query ListGlobalPythonModules($input: ListGlobalPythonModuleInput!) {
    listGlobalPythonModules(input: $input) {
      globals {
        ...GlobalPythonModuleTeaser
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
  ${GlobalPythonModuleTeaser}
`;

/**
 * __useListGlobalPythonModules__
 *
 * To run a query within a React component, call `useListGlobalPythonModules` and pass it any options that fit your needs.
 * When your component renders, `useListGlobalPythonModules` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListGlobalPythonModules({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListGlobalPythonModules(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListGlobalPythonModules,
    ListGlobalPythonModulesVariables
  >
) {
  return ApolloReactHooks.useQuery<ListGlobalPythonModules, ListGlobalPythonModulesVariables>(
    ListGlobalPythonModulesDocument,
    baseOptions
  );
}
export function useListGlobalPythonModulesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListGlobalPythonModules,
    ListGlobalPythonModulesVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListGlobalPythonModules, ListGlobalPythonModulesVariables>(
    ListGlobalPythonModulesDocument,
    baseOptions
  );
}
export type ListGlobalPythonModulesHookResult = ReturnType<typeof useListGlobalPythonModules>;
export type ListGlobalPythonModulesLazyQueryHookResult = ReturnType<
  typeof useListGlobalPythonModulesLazyQuery
>;
export type ListGlobalPythonModulesQueryResult = ApolloReactCommon.QueryResult<
  ListGlobalPythonModules,
  ListGlobalPythonModulesVariables
>;
export function mockListGlobalPythonModules({
  data,
  variables,
  errors,
}: {
  data: ListGlobalPythonModules;
  variables?: ListGlobalPythonModulesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListGlobalPythonModulesDocument, variables },
    result: { data, errors },
  };
}
