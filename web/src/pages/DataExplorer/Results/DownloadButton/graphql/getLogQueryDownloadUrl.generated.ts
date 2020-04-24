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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetLogQueryDownloadUrlVariables = {
  input: Types.GetLogQueryInput;
};

export type GetLogQueryDownloadUrl = {
  getLogQueryDownloadUrl: Pick<Types.GetLogQueryDownloadUrlOutput, 'url'> & {
    error?: Types.Maybe<Pick<Types.Error, 'message'>>;
  };
};

export const GetLogQueryDownloadUrlDocument = gql`
  query GetLogQueryDownloadUrl($input: GetLogQueryInput!) {
    getLogQueryDownloadUrl(input: $input) {
      url
      error {
        message
      }
    }
  }
`;

/**
 * __useGetLogQueryDownloadUrl__
 *
 * To run a query within a React component, call `useGetLogQueryDownloadUrl` and pass it any options that fit your needs.
 * When your component renders, `useGetLogQueryDownloadUrl` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetLogQueryDownloadUrl({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetLogQueryDownloadUrl(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GetLogQueryDownloadUrl,
    GetLogQueryDownloadUrlVariables
  >
) {
  return ApolloReactHooks.useQuery<GetLogQueryDownloadUrl, GetLogQueryDownloadUrlVariables>(
    GetLogQueryDownloadUrlDocument,
    baseOptions
  );
}
export function useGetLogQueryDownloadUrlLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetLogQueryDownloadUrl,
    GetLogQueryDownloadUrlVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetLogQueryDownloadUrl, GetLogQueryDownloadUrlVariables>(
    GetLogQueryDownloadUrlDocument,
    baseOptions
  );
}
export type GetLogQueryDownloadUrlHookResult = ReturnType<typeof useGetLogQueryDownloadUrl>;
export type GetLogQueryDownloadUrlLazyQueryHookResult = ReturnType<
  typeof useGetLogQueryDownloadUrlLazyQuery
>;
export type GetLogQueryDownloadUrlQueryResult = ApolloReactCommon.QueryResult<
  GetLogQueryDownloadUrl,
  GetLogQueryDownloadUrlVariables
>;
