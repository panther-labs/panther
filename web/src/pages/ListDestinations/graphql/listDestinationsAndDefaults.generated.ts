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

import { DestinationFull } from '../../../graphql/fragments/DestinationFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListDestinationsAndDefaultsVariables = {};

export type ListDestinationsAndDefaults = {
  destinations?: Types.Maybe<Array<Types.Maybe<DestinationFull>>>;
};

export const ListDestinationsAndDefaultsDocument = gql`
  query ListDestinationsAndDefaults {
    destinations {
      ...DestinationFull
    }
  }
  ${DestinationFull}
`;

/**
 * __useListDestinationsAndDefaults__
 *
 * To run a query within a React component, call `useListDestinationsAndDefaults` and pass it any options that fit your needs.
 * When your component renders, `useListDestinationsAndDefaults` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListDestinationsAndDefaults({
 *   variables: {
 *   },
 * });
 */
export function useListDestinationsAndDefaults(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >
) {
  return ApolloReactHooks.useQuery<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >(ListDestinationsAndDefaultsDocument, baseOptions);
}
export function useListDestinationsAndDefaultsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<
    ListDestinationsAndDefaults,
    ListDestinationsAndDefaultsVariables
  >(ListDestinationsAndDefaultsDocument, baseOptions);
}
export type ListDestinationsAndDefaultsHookResult = ReturnType<
  typeof useListDestinationsAndDefaults
>;
export type ListDestinationsAndDefaultsLazyQueryHookResult = ReturnType<
  typeof useListDestinationsAndDefaultsLazyQuery
>;
export type ListDestinationsAndDefaultsQueryResult = ApolloReactCommon.QueryResult<
  ListDestinationsAndDefaults,
  ListDestinationsAndDefaultsVariables
>;
export function mockListDestinationsAndDefaults({
  data,
  variables,
  errors,
}: {
  data: ListDestinationsAndDefaults;
  variables?: ListDestinationsAndDefaultsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListDestinationsAndDefaultsDocument, variables },
    result: { data, errors },
  };
}
