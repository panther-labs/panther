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

import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetLogQueryResultsVariables = {
  input: Types.GetLogQueryInput;
};

export type GetLogQueryResults = {
  getLogQuery: {
    error?: Types.Maybe<Pick<Types.Error, 'message'>>;
    query?: Types.Maybe<Pick<Types.LogQueryOutputQueryData, 'status'>>;
    stats?: Types.Maybe<
      Pick<Types.GetLogQueryStats, 'executionTimeMilliseconds' | 'dataScannedBytes'>
    >;
    results?: Types.Maybe<Array<Array<Pick<Types.LogColumn, 'key' | 'value'>>>>;
    pageInfo: Pick<Types.PageInfo, 'hasNextPage' | 'paginationToken'>;
  };
};

export const GetLogQueryResultsDocument = gql`
  query GetLogQueryResults($input: GetLogQueryInput!) {
    getLogQuery(input: $input) {
      error {
        message
      }
      query {
        status
      }
      stats {
        executionTimeMilliseconds
        dataScannedBytes
      }
      results {
        key
        value
      }
      pageInfo {
        hasNextPage
        paginationToken
      }
    }
  }
`;

/**
 * __useGetLogQueryResults__
 *
 * To run a query within a React component, call `useGetLogQueryResults` and pass it any options that fit your needs.
 * When your component renders, `useGetLogQueryResults` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetLogQueryResults({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetLogQueryResults(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetLogQueryResults, GetLogQueryResultsVariables>
) {
  return ApolloReactHooks.useQuery<GetLogQueryResults, GetLogQueryResultsVariables>(
    GetLogQueryResultsDocument,
    baseOptions
  );
}
export function useGetLogQueryResultsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetLogQueryResults,
    GetLogQueryResultsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetLogQueryResults, GetLogQueryResultsVariables>(
    GetLogQueryResultsDocument,
    baseOptions
  );
}
export type GetLogQueryResultsHookResult = ReturnType<typeof useGetLogQueryResults>;
export type GetLogQueryResultsLazyQueryHookResult = ReturnType<
  typeof useGetLogQueryResultsLazyQuery
>;
export type GetLogQueryResultsQueryResult = ApolloReactCommon.QueryResult<
  GetLogQueryResults,
  GetLogQueryResultsVariables
>;
