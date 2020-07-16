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

import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetLogAnalysisMetricsVariables = {
  input?: Types.Maybe<Types.LogAnalysisMetricsInput>;
};

export type GetLogAnalysisMetrics = {
  getLogAnalysisMetrics?: Types.Maybe<
    Pick<Types.LogAnalysisMetricsResponse, 'intervalHours'> & {
      metricResults?: Types.Maybe<
        Array<
          Types.Maybe<
            Pick<Types.MetricsResults, 'MetricsName'> & {
              seriesData?: Types.Maybe<
                Array<Types.Maybe<Pick<Types.SeriesData, 'Label' | 'Timestamps' | 'Values'>>>
              >;
            }
          >
        >
      >;
    }
  >;
};

export const GetLogAnalysisMetricsDocument = gql`
  query GetLogAnalysisMetrics($input: LogAnalysisMetricsInput) {
    getLogAnalysisMetrics(input: $input) {
      metricResults {
        MetricsName
        seriesData {
          Label
          Timestamps
          Values
        }
      }
      intervalHours
    }
  }
`;

/**
 * __useGetLogAnalysisMetrics__
 *
 * To run a query within a React component, call `useGetLogAnalysisMetrics` and pass it any options that fit your needs.
 * When your component renders, `useGetLogAnalysisMetrics` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetLogAnalysisMetrics({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetLogAnalysisMetrics(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GetLogAnalysisMetrics,
    GetLogAnalysisMetricsVariables
  >
) {
  return ApolloReactHooks.useQuery<GetLogAnalysisMetrics, GetLogAnalysisMetricsVariables>(
    GetLogAnalysisMetricsDocument,
    baseOptions
  );
}
export function useGetLogAnalysisMetricsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetLogAnalysisMetrics,
    GetLogAnalysisMetricsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetLogAnalysisMetrics, GetLogAnalysisMetricsVariables>(
    GetLogAnalysisMetricsDocument,
    baseOptions
  );
}
export type GetLogAnalysisMetricsHookResult = ReturnType<typeof useGetLogAnalysisMetrics>;
export type GetLogAnalysisMetricsLazyQueryHookResult = ReturnType<
  typeof useGetLogAnalysisMetricsLazyQuery
>;
export type GetLogAnalysisMetricsQueryResult = ApolloReactCommon.QueryResult<
  GetLogAnalysisMetrics,
  GetLogAnalysisMetricsVariables
>;
