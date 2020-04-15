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

import * as Types from '../../../../../../__generated__/schema';

import { LogDatabaseTableSummary } from '../../../../../graphql/fragments/LogDatabaseTableSummary.generated';
import { LogDatabaseTableColumnDetails } from '../../../../../graphql/fragments/LogDatabaseTableColumnDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListColumnsForTableVariables = {
  input: Types.GetLogDatabaseTableInput;
};

export type ListColumnsForTable = {
  getLogDatabaseTable?: Types.Maybe<
    { columns: Array<LogDatabaseTableColumnDetails> } & LogDatabaseTableSummary
  >;
};

export const ListColumnsForTableDocument = gql`
  query ListColumnsForTable($input: GetLogDatabaseTableInput!) {
    getLogDatabaseTable(input: $input) {
      ...LogDatabaseTableSummary
      columns {
        ...LogDatabaseTableColumnDetails
      }
    }
  }
  ${LogDatabaseTableSummary}
  ${LogDatabaseTableColumnDetails}
`;

/**
 * __useListColumnsForTable__
 *
 * To run a query within a React component, call `useListColumnsForTable` and pass it any options that fit your needs.
 * When your component renders, `useListColumnsForTable` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListColumnsForTable({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListColumnsForTable(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListColumnsForTable, ListColumnsForTableVariables>
) {
  return ApolloReactHooks.useQuery<ListColumnsForTable, ListColumnsForTableVariables>(
    ListColumnsForTableDocument,
    baseOptions
  );
}
export function useListColumnsForTableLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListColumnsForTable,
    ListColumnsForTableVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListColumnsForTable, ListColumnsForTableVariables>(
    ListColumnsForTableDocument,
    baseOptions
  );
}
export type ListColumnsForTableHookResult = ReturnType<typeof useListColumnsForTable>;
export type ListColumnsForTableLazyQueryHookResult = ReturnType<
  typeof useListColumnsForTableLazyQuery
>;
export type ListColumnsForTableQueryResult = ApolloReactCommon.QueryResult<
  ListColumnsForTable,
  ListColumnsForTableVariables
>;
