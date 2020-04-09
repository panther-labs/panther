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

import * as Types from '../../../../../../__generated__/schema';

import { LogDatabaseSummary } from '../../../../../graphql/fragments/LogDatabaseSummary.generated';
import { LogDatabaseTableSummary } from '../../../../../graphql/fragments/LogDatabaseTableSummary.generated';
import { LogDatabaseTableColumnDetails } from '../../../../../graphql/fragments/LogDatabaseTableColumnDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListTablesForDatabaseVariables = {
  name: Types.Scalars['String'];
};

export type ListTablesForDatabase = {
  getLogDatabase?: Types.Maybe<
    {
      tables: Array<{ columns: Array<LogDatabaseTableColumnDetails> } & LogDatabaseTableSummary>;
    } & LogDatabaseSummary
  >;
};

export const ListTablesForDatabaseDocument = gql`
  query ListTablesForDatabase($name: String!) {
    getLogDatabase(name: $name) {
      ...LogDatabaseSummary
      tables {
        ...LogDatabaseTableSummary
        columns {
          ...LogDatabaseTableColumnDetails
        }
      }
    }
  }
  ${LogDatabaseSummary}
  ${LogDatabaseTableSummary}
  ${LogDatabaseTableColumnDetails}
`;

/**
 * __useListTablesForDatabase__
 *
 * To run a query within a React component, call `useListTablesForDatabase` and pass it any options that fit your needs.
 * When your component renders, `useListTablesForDatabase` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListTablesForDatabase({
 *   variables: {
 *      name: // value for 'name'
 *   },
 * });
 */
export function useListTablesForDatabase(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListTablesForDatabase,
    ListTablesForDatabaseVariables
  >
) {
  return ApolloReactHooks.useQuery<ListTablesForDatabase, ListTablesForDatabaseVariables>(
    ListTablesForDatabaseDocument,
    baseOptions
  );
}
export function useListTablesForDatabaseLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListTablesForDatabase,
    ListTablesForDatabaseVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListTablesForDatabase, ListTablesForDatabaseVariables>(
    ListTablesForDatabaseDocument,
    baseOptions
  );
}
export type ListTablesForDatabaseHookResult = ReturnType<typeof useListTablesForDatabase>;
export type ListTablesForDatabaseLazyQueryHookResult = ReturnType<
  typeof useListTablesForDatabaseLazyQuery
>;
export type ListTablesForDatabaseQueryResult = ApolloReactCommon.QueryResult<
  ListTablesForDatabase,
  ListTablesForDatabaseVariables
>;
