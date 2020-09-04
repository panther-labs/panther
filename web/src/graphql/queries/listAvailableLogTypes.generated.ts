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

import * as Types from '../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListAvailableLogTypesVariables = {};

export type ListAvailableLogTypes = {
  listAvailableLogTypes: Pick<Types.ListAvailableLogTypesResponse, 'logTypes'>;
};

export const ListAvailableLogTypesDocument = gql`
  query ListAvailableLogTypes {
    listAvailableLogTypes {
      logTypes
    }
  }
`;

/**
 * __useListAvailableLogTypes__
 *
 * To run a query within a React component, call `useListAvailableLogTypes` and pass it any options that fit your needs.
 * When your component renders, `useListAvailableLogTypes` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListAvailableLogTypes({
 *   variables: {
 *   },
 * });
 */
export function useListAvailableLogTypes(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListAvailableLogTypes,
    ListAvailableLogTypesVariables
  >
) {
  return ApolloReactHooks.useQuery<ListAvailableLogTypes, ListAvailableLogTypesVariables>(
    ListAvailableLogTypesDocument,
    baseOptions
  );
}
export function useListAvailableLogTypesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListAvailableLogTypes,
    ListAvailableLogTypesVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListAvailableLogTypes, ListAvailableLogTypesVariables>(
    ListAvailableLogTypesDocument,
    baseOptions
  );
}
export type ListAvailableLogTypesHookResult = ReturnType<typeof useListAvailableLogTypes>;
export type ListAvailableLogTypesLazyQueryHookResult = ReturnType<
  typeof useListAvailableLogTypesLazyQuery
>;
export type ListAvailableLogTypesQueryResult = ApolloReactCommon.QueryResult<
  ListAvailableLogTypes,
  ListAvailableLogTypesVariables
>;
export function mockListAvailableLogTypes({
  data,
  variables,
  errors,
}: {
  data: ListAvailableLogTypes;
  variables?: ListAvailableLogTypesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListAvailableLogTypesDocument, variables },
    result: { data, errors },
  };
}
