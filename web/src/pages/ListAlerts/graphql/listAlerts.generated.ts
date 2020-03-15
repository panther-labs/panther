/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListAlertsVariables = {
  input?: Types.Maybe<Types.ListAlertsInput>;
};

export type ListAlerts = {
  alerts: Types.Maybe<
    Pick<Types.ListAlertsResponse, 'lastEvaluatedKey'> & {
      alertSummaries: Array<
        Types.Maybe<
          Pick<
            Types.AlertSummary,
            'alertId' | 'creationTime' | 'eventsMatched' | 'updateTime' | 'ruleId' | 'severity'
          >
        >
      >;
    }
  >;
};

export const ListAlertsDocument = gql`
  query ListAlerts($input: ListAlertsInput) {
    alerts(input: $input) {
      alertSummaries {
        alertId
        creationTime
        eventsMatched
        updateTime
        ruleId
        severity
      }
      lastEvaluatedKey
    }
  }
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
