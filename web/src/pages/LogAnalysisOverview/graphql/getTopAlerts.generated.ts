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

export type GetTopAlertsVariables = {};

export type GetTopAlerts = {
  alerts?: Types.Maybe<{ alertSummaries: Array<Types.Maybe<AlertSummaryFull>> }>;
};

export const GetTopAlertsDocument = gql`
  query GetTopAlerts {
    alerts(input: { severity: [CRITICAL, HIGH], pageSize: 10 }) {
      alertSummaries {
        ...AlertSummaryFull
      }
    }
  }
  ${AlertSummaryFull}
`;

/**
 * __useGetTopAlerts__
 *
 * To run a query within a React component, call `useGetTopAlerts` and pass it any options that fit your needs.
 * When your component renders, `useGetTopAlerts` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetTopAlerts({
 *   variables: {
 *   },
 * });
 */
export function useGetTopAlerts(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetTopAlerts, GetTopAlertsVariables>
) {
  return ApolloReactHooks.useQuery<GetTopAlerts, GetTopAlertsVariables>(
    GetTopAlertsDocument,
    baseOptions
  );
}
export function useGetTopAlertsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetTopAlerts, GetTopAlertsVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetTopAlerts, GetTopAlertsVariables>(
    GetTopAlertsDocument,
    baseOptions
  );
}
export type GetTopAlertsHookResult = ReturnType<typeof useGetTopAlerts>;
export type GetTopAlertsLazyQueryHookResult = ReturnType<typeof useGetTopAlertsLazyQuery>;
export type GetTopAlertsQueryResult = ApolloReactCommon.QueryResult<
  GetTopAlerts,
  GetTopAlertsVariables
>;
export function mockGetTopAlerts({
  data,
  variables,
  errors,
}: {
  data: GetTopAlerts;
  variables?: GetTopAlertsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetTopAlertsDocument, variables },
    result: { data, errors },
  };
}
