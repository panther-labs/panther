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

/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListLogSourcesVariables = {};

export type ListLogSources = {
  integrations?: Types.Maybe<
    Array<
      Pick<
        Types.Integration,
        | 'awsAccountId'
        | 'createdAtTime'
        | 'integrationId'
        | 'integrationLabel'
        | 'integrationType'
        | 's3Buckets'
      >
    >
  >;
};

export const ListLogSourcesDocument = gql`
  query ListLogSources {
    integrations(input: { integrationType: "aws-s3" }) {
      awsAccountId
      createdAtTime
      integrationId
      integrationLabel
      integrationType
      s3Buckets
    }
  }
`;

/**
 * __useListLogSources__
 *
 * To run a query within a React component, call `useListLogSources` and pass it any options that fit your needs.
 * When your component renders, `useListLogSources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListLogSources({
 *   variables: {
 *   },
 * });
 */
export function useListLogSources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListLogSources, ListLogSourcesVariables>
) {
  return ApolloReactHooks.useQuery<ListLogSources, ListLogSourcesVariables>(
    ListLogSourcesDocument,
    baseOptions
  );
}
export function useListLogSourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListLogSources, ListLogSourcesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListLogSources, ListLogSourcesVariables>(
    ListLogSourcesDocument,
    baseOptions
  );
}
export type ListLogSourcesHookResult = ReturnType<typeof useListLogSources>;
export type ListLogSourcesLazyQueryHookResult = ReturnType<typeof useListLogSourcesLazyQuery>;
export type ListLogSourcesQueryResult = ApolloReactCommon.QueryResult<
  ListLogSources,
  ListLogSourcesVariables
>;
