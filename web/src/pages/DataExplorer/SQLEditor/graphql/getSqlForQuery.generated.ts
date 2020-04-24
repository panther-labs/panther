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

import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetSqlForQueryVariables = {
  input: Types.GetLogQueryInput;
};

export type GetSqlForQuery = {
  getLogQuery: { query?: Types.Maybe<Pick<Types.LogQueryOutputQueryData, 'sql'>> };
};

export const GetSqlForQueryDocument = gql`
  query GetSqlForQuery($input: GetLogQueryInput!) {
    getLogQuery(input: $input) {
      query {
        sql
      }
    }
  }
`;

/**
 * __useGetSqlForQuery__
 *
 * To run a query within a React component, call `useGetSqlForQuery` and pass it any options that fit your needs.
 * When your component renders, `useGetSqlForQuery` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetSqlForQuery({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetSqlForQuery(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetSqlForQuery, GetSqlForQueryVariables>
) {
  return ApolloReactHooks.useQuery<GetSqlForQuery, GetSqlForQueryVariables>(
    GetSqlForQueryDocument,
    baseOptions
  );
}
export function useGetSqlForQueryLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetSqlForQuery, GetSqlForQueryVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetSqlForQuery, GetSqlForQueryVariables>(
    GetSqlForQueryDocument,
    baseOptions
  );
}
export type GetSqlForQueryHookResult = ReturnType<typeof useGetSqlForQuery>;
export type GetSqlForQueryLazyQueryHookResult = ReturnType<typeof useGetSqlForQueryLazyQuery>;
export type GetSqlForQueryQueryResult = ApolloReactCommon.QueryResult<
  GetSqlForQuery,
  GetSqlForQueryVariables
>;
