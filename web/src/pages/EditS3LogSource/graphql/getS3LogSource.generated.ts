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

import { S3LogIntegrationDetails } from '../../../graphql/fragments/S3LogIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetS3LogSourceVariables = {
  id: Types.Scalars['ID'];
};

export type GetS3LogSource = { getS3LogIntegration: S3LogIntegrationDetails };

export const GetS3LogSourceDocument = gql`
  query GetS3LogSource($id: ID!) {
    getS3LogIntegration(id: $id) {
      ...S3LogIntegrationDetails
    }
  }
  ${S3LogIntegrationDetails}
`;

/**
 * __useGetS3LogSource__
 *
 * To run a query within a React component, call `useGetS3LogSource` and pass it any options that fit your needs.
 * When your component renders, `useGetS3LogSource` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetS3LogSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useGetS3LogSource(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetS3LogSource, GetS3LogSourceVariables>
) {
  return ApolloReactHooks.useQuery<GetS3LogSource, GetS3LogSourceVariables>(
    GetS3LogSourceDocument,
    baseOptions
  );
}
export function useGetS3LogSourceLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetS3LogSource, GetS3LogSourceVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetS3LogSource, GetS3LogSourceVariables>(
    GetS3LogSourceDocument,
    baseOptions
  );
}
export type GetS3LogSourceHookResult = ReturnType<typeof useGetS3LogSource>;
export type GetS3LogSourceLazyQueryHookResult = ReturnType<typeof useGetS3LogSourceLazyQuery>;
export type GetS3LogSourceQueryResult = ApolloReactCommon.QueryResult<
  GetS3LogSource,
  GetS3LogSourceVariables
>;
export function mockGetS3LogSource({
  data,
  variables,
  errors,
}: {
  data: GetS3LogSource;
  variables?: GetS3LogSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetS3LogSourceDocument, variables },
    result: { data, errors },
  };
}
