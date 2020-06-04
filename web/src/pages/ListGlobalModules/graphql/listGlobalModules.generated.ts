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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListGlobalModulesVariables = {
  input?: Types.Maybe<Types.ListGlobalModuleInput>;
};

export type ListGlobalModules = {
  listGlobalModules?: Types.Maybe<{
    globals?: Types.Maybe<Array<Types.Maybe<Pick<Types.GlobalModule, 'id'>>>>;
    paging?: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
  }>;
};

export const ListGlobalModulesDocument = gql`
  query ListGlobalModules($input: ListGlobalModuleInput) {
    listGlobalModules(input: $input) {
      globals {
        id
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
`;

/**
 * __useListGlobalModules__
 *
 * To run a query within a React component, call `useListGlobalModules` and pass it any options that fit your needs.
 * When your component renders, `useListGlobalModules` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListGlobalModules({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListGlobalModules(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListGlobalModules, ListGlobalModulesVariables>
) {
  return ApolloReactHooks.useQuery<ListGlobalModules, ListGlobalModulesVariables>(
    ListGlobalModulesDocument,
    baseOptions
  );
}
export function useListGlobalModulesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListGlobalModules, ListGlobalModulesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListGlobalModules, ListGlobalModulesVariables>(
    ListGlobalModulesDocument,
    baseOptions
  );
}
export type ListGlobalModulesHookResult = ReturnType<typeof useListGlobalModules>;
export type ListGlobalModulesLazyQueryHookResult = ReturnType<typeof useListGlobalModulesLazyQuery>;
export type ListGlobalModulesQueryResult = ApolloReactCommon.QueryResult<
  ListGlobalModules,
  ListGlobalModulesVariables
>;
