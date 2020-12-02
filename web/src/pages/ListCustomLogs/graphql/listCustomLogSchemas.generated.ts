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

import { CustomLogTeaser } from '../../../graphql/fragments/CustomLogTeaser.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListCustomLogSchemasVariables = {};

export type ListCustomLogSchemas = { listCustomLogs: Array<CustomLogTeaser> };

export const ListCustomLogSchemasDocument = gql`
  query ListCustomLogSchemas {
    listCustomLogs {
      ...CustomLogTeaser
    }
  }
  ${CustomLogTeaser}
`;

/**
 * __useListCustomLogSchemas__
 *
 * To run a query within a React component, call `useListCustomLogSchemas` and pass it any options that fit your needs.
 * When your component renders, `useListCustomLogSchemas` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListCustomLogSchemas({
 *   variables: {
 *   },
 * });
 */
export function useListCustomLogSchemas(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListCustomLogSchemas,
    ListCustomLogSchemasVariables
  >
) {
  return ApolloReactHooks.useQuery<ListCustomLogSchemas, ListCustomLogSchemasVariables>(
    ListCustomLogSchemasDocument,
    baseOptions
  );
}
export function useListCustomLogSchemasLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListCustomLogSchemas,
    ListCustomLogSchemasVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListCustomLogSchemas, ListCustomLogSchemasVariables>(
    ListCustomLogSchemasDocument,
    baseOptions
  );
}
export type ListCustomLogSchemasHookResult = ReturnType<typeof useListCustomLogSchemas>;
export type ListCustomLogSchemasLazyQueryHookResult = ReturnType<
  typeof useListCustomLogSchemasLazyQuery
>;
export type ListCustomLogSchemasQueryResult = ApolloReactCommon.QueryResult<
  ListCustomLogSchemas,
  ListCustomLogSchemasVariables
>;
export function mockListCustomLogSchemas({
  data,
  variables,
  errors,
}: {
  data: ListCustomLogSchemas;
  variables?: ListCustomLogSchemasVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListCustomLogSchemasDocument, variables },
    result: { data, errors },
  };
}
