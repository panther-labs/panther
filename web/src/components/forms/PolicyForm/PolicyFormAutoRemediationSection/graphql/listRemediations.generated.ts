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

import * as Types from '../../../../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListRemediationsVariables = {};

export type ListRemediations = Pick<Types.Query, 'remediations'>;

export const ListRemediationsDocument = gql`
  query ListRemediations {
    remediations
  }
`;

/**
 * __useListRemediations__
 *
 * To run a query within a React component, call `useListRemediations` and pass it any options that fit your needs.
 * When your component renders, `useListRemediations` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListRemediations({
 *   variables: {
 *   },
 * });
 */
export function useListRemediations(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListRemediations, ListRemediationsVariables>
) {
  return ApolloReactHooks.useQuery<ListRemediations, ListRemediationsVariables>(
    ListRemediationsDocument,
    baseOptions
  );
}
export function useListRemediationsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListRemediations, ListRemediationsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListRemediations, ListRemediationsVariables>(
    ListRemediationsDocument,
    baseOptions
  );
}
export type ListRemediationsHookResult = ReturnType<typeof useListRemediations>;
export type ListRemediationsLazyQueryHookResult = ReturnType<typeof useListRemediationsLazyQuery>;
export type ListRemediationsQueryResult = ApolloReactCommon.QueryResult<
  ListRemediations,
  ListRemediationsVariables
>;
export function mockListRemediations({
  data,
  variables,
  errors,
}: {
  data: ListRemediations;
  variables?: ListRemediationsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListRemediationsDocument, variables },
    result: { data, errors },
  };
}
