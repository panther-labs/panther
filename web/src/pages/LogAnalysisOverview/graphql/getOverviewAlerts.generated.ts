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

export type GetOverviewAlertsVariables = {
  recentAlertsInput?: Types.Maybe<Types.ListAlertsInput>;
};

export type GetOverviewAlerts = {
  topAlerts?: Types.Maybe<{ alertSummaries: Array<Types.Maybe<AlertSummaryFull>> }>;
  recentAlerts?: Types.Maybe<{ alertSummaries: Array<Types.Maybe<AlertSummaryFull>> }>;
};

export const GetOverviewAlertsDocument = gql`
  query GetOverviewAlerts($recentAlertsInput: ListAlertsInput) {
    topAlerts: alerts(
      input: { severity: [CRITICAL, HIGH], pageSize: 10, status: [OPEN, TRIAGED] }
    ) {
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
 * __useGetOverviewAlerts__
 *
 * To run a query within a React component, call `useGetOverviewAlerts` and pass it any options that fit your needs.
 * When your component renders, `useGetOverviewAlerts` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetOverviewAlerts({
 *   variables: {
 *      recentAlertsInput: // value for 'recentAlertsInput'
 *   },
 * });
 */
export function useGetOverviewAlerts(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetOverviewAlerts, GetOverviewAlertsVariables>
) {
  return ApolloReactHooks.useQuery<GetOverviewAlerts, GetOverviewAlertsVariables>(
    GetOverviewAlertsDocument,
    baseOptions
  );
}
export function useGetOverviewAlertsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetOverviewAlerts, GetOverviewAlertsVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetOverviewAlerts, GetOverviewAlertsVariables>(
    GetOverviewAlertsDocument,
    baseOptions
  );
}
export type GetOverviewAlertsHookResult = ReturnType<typeof useGetOverviewAlerts>;
export type GetOverviewAlertsLazyQueryHookResult = ReturnType<typeof useGetOverviewAlertsLazyQuery>;
export type GetOverviewAlertsQueryResult = ApolloReactCommon.QueryResult<
  GetOverviewAlerts,
  GetOverviewAlertsVariables
>;
export function mockGetOverviewAlerts({
  data,
  variables,
  errors,
}: {
  data: GetOverviewAlerts;
  variables?: GetOverviewAlertsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetOverviewAlertsDocument, variables },
    result: { data, errors },
  };
}
