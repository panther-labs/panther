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

import { AlertSummaryFull } from '../../../graphql/fragments/AlertSummaryFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetAlertsVariables = {
  recentAlertsInput?: Types.Maybe<Types.ListAlertsInput>;
};

export type GetAlerts = {
  topAlerts?: Types.Maybe<{ alertSummaries: Array<Types.Maybe<AlertSummaryFull>> }>;
  recentAlerts?: Types.Maybe<{ alertSummaries: Array<Types.Maybe<AlertSummaryFull>> }>;
};

export const GetAlertsDocument = gql`
  query GetAlerts($recentAlertsInput: ListAlertsInput) {
    topAlerts: alerts(input: { severity: [CRITICAL, HIGH], pageSize: 10 }) {
      alertSummaries {
        ...AlertSummaryFull
      }
    }
    recentAlerts: alerts(input: $recentAlertsInput) {
      alertSummaries {
        ...AlertSummaryFull
      }
    }
  }
  ${AlertSummaryFull}
`;

/**
 * __useGetAlerts__
 *
 * To run a query within a React component, call `useGetAlerts` and pass it any options that fit your needs.
 * When your component renders, `useGetAlerts` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetAlerts({
 *   variables: {
 *      recentAlertsInput: // value for 'recentAlertsInput'
 *   },
 * });
 */
export function useGetAlerts(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetAlerts, GetAlertsVariables>
) {
  return ApolloReactHooks.useQuery<GetAlerts, GetAlertsVariables>(GetAlertsDocument, baseOptions);
}
export function useGetAlertsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetAlerts, GetAlertsVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetAlerts, GetAlertsVariables>(
    GetAlertsDocument,
    baseOptions
  );
}
export type GetAlertsHookResult = ReturnType<typeof useGetAlerts>;
export type GetAlertsLazyQueryHookResult = ReturnType<typeof useGetAlertsLazyQuery>;
export type GetAlertsQueryResult = ApolloReactCommon.QueryResult<GetAlerts, GetAlertsVariables>;
export function mockGetAlerts({
  data,
  variables,
  errors,
}: {
  data: GetAlerts;
  variables?: GetAlertsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetAlertsDocument, variables },
    result: { data, errors },
  };
}
