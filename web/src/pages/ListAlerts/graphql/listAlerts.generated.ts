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

export type ListAlertsVariables = {
  input?: Types.Maybe<Types.ListAlertsInput>;
};

export type ListAlerts = {
  alerts?: Types.Maybe<
    Pick<Types.ListAlertsResponse, 'lastEvaluatedKey'> & {
      alertSummaries: Array<Types.Maybe<AlertSummaryFull>>;
    }
  >;
};

export const ListAlertsDocument = gql`
  query ListAlerts($input: ListAlertsInput) {
    alerts(input: $input) {
      alertSummaries {
        ...AlertSummaryFull
      }
      lastEvaluatedKey
    }
  }
  ${AlertSummaryFull}
`;

/**
 * __useListAlerts__
 *
 * To run a query within a React component, call `useListAlerts` and pass it any options that fit your needs.
 * When your component renders, `useListAlerts` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListAlerts({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListAlerts(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListAlerts, ListAlertsVariables>
) {
  return ApolloReactHooks.useQuery<ListAlerts, ListAlertsVariables>(
    ListAlertsDocument,
    baseOptions
  );
}
export function useListAlertsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListAlerts, ListAlertsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListAlerts, ListAlertsVariables>(
    ListAlertsDocument,
    baseOptions
  );
}
export type ListAlertsHookResult = ReturnType<typeof useListAlerts>;
export type ListAlertsLazyQueryHookResult = ReturnType<typeof useListAlertsLazyQuery>;
export type ListAlertsQueryResult = ApolloReactCommon.QueryResult<ListAlerts, ListAlertsVariables>;
export function mockListAlerts({
  data,
  variables,
  errors,
}: {
  data: ListAlerts;
  variables?: ListAlertsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListAlertsDocument, variables },
    result: { data, errors },
  };
}
