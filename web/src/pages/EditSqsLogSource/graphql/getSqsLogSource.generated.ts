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

import { SqsLogSourceIntegrationDetails } from '../../../graphql/fragments/SqsLogSourceIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetSqsLogSourceVariables = {
  id: Types.Scalars['ID'];
};

export type GetSqsLogSource = { getSqsLogIntegration: SqsLogSourceIntegrationDetails };

export const GetSqsLogSourceDocument = gql`
  query GetSqsLogSource($id: ID!) {
    getSqsLogIntegration(id: $id) {
      ...SqsLogSourceIntegrationDetails
    }
  }
  ${SqsLogSourceIntegrationDetails}
`;

/**
 * __useGetSqsLogSource__
 *
 * To run a query within a React component, call `useGetSqsLogSource` and pass it any options that fit your needs.
 * When your component renders, `useGetSqsLogSource` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetSqsLogSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useGetSqsLogSource(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetSqsLogSource, GetSqsLogSourceVariables>
) {
  return ApolloReactHooks.useQuery<GetSqsLogSource, GetSqsLogSourceVariables>(
    GetSqsLogSourceDocument,
    baseOptions
  );
}
export function useGetSqsLogSourceLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetSqsLogSource, GetSqsLogSourceVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetSqsLogSource, GetSqsLogSourceVariables>(
    GetSqsLogSourceDocument,
    baseOptions
  );
}
export type GetSqsLogSourceHookResult = ReturnType<typeof useGetSqsLogSource>;
export type GetSqsLogSourceLazyQueryHookResult = ReturnType<typeof useGetSqsLogSourceLazyQuery>;
export type GetSqsLogSourceQueryResult = ApolloReactCommon.QueryResult<
  GetSqsLogSource,
  GetSqsLogSourceVariables
>;
export function mockGetSqsLogSource({
  data,
  variables,
  errors,
}: {
  data: GetSqsLogSource;
  variables?: GetSqsLogSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetSqsLogSourceDocument, variables },
    result: { data, errors },
  };
}
