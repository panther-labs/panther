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

export type ListDestinationsVariables = {};

export type ListDestinations = {
  destinations?: Types.Maybe<
    Array<
      Types.Maybe<
        Pick<
          Types.Destination,
          'outputId' | 'outputType' | 'displayName' | 'defaultForSeverity' | 'alertTypes'
        >
      >
    >
  >;
};

export const ListDestinationsDocument = gql`
  query ListDestinations {
    destinations {
      outputId
      outputType
      displayName
      defaultForSeverity
      alertTypes
    }
  }
`;

/**
 * __useListDestinations__
 *
 * To run a query within a React component, call `useListDestinations` and pass it any options that fit your needs.
 * When your component renders, `useListDestinations` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListDestinations({
 *   variables: {
 *   },
 * });
 */
export function useListDestinations(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListDestinations, ListDestinationsVariables>
) {
  return ApolloReactHooks.useQuery<ListDestinations, ListDestinationsVariables>(
    ListDestinationsDocument,
    baseOptions
  );
}
export function useListDestinationsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListDestinations, ListDestinationsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListDestinations, ListDestinationsVariables>(
    ListDestinationsDocument,
    baseOptions
  );
}
export type ListDestinationsHookResult = ReturnType<typeof useListDestinations>;
export type ListDestinationsLazyQueryHookResult = ReturnType<typeof useListDestinationsLazyQuery>;
export type ListDestinationsQueryResult = ApolloReactCommon.QueryResult<
  ListDestinations,
  ListDestinationsVariables
>;
export function mockListDestinations({
  data,
  variables,
  errors,
}: {
  data: ListDestinations;
  variables?: ListDestinationsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListDestinationsDocument, variables },
    result: { data, errors },
  };
}
