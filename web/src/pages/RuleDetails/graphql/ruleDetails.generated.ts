/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type RuleDetailsVariables = {
  ruleDetailsInput: Types.GetRuleInput;
  alertsForRuleInput: Types.ListAlertsInput;
};

export type RuleDetails = {
  rule: Types.Maybe<
    Pick<
      Types.RuleDetails,
      | 'createdAt'
      | 'description'
      | 'displayName'
      | 'enabled'
      | 'id'
      | 'lastModified'
      | 'reference'
      | 'logTypes'
      | 'runbook'
      | 'severity'
      | 'tags'
    >
  >;
  alerts: Types.Maybe<{
    alertSummaries: Array<Types.Maybe<Pick<Types.AlertSummary, 'alertId' | 'creationTime'>>>;
  }>;
};

export const RuleDetailsDocument = gql`
  query RuleDetails($ruleDetailsInput: GetRuleInput!, $alertsForRuleInput: ListAlertsInput!) {
    rule(input: $ruleDetailsInput) {
      createdAt
      description
      displayName
      enabled
      id
      lastModified
      reference
      logTypes
      runbook
      severity
      tags
    }
    alerts(input: $alertsForRuleInput) {
      alertSummaries {
        alertId
        creationTime
      }
    }
  }
`;

/**
 * __useRuleDetails__
 *
 * To run a query within a React component, call `useRuleDetails` and pass it any options that fit your needs.
 * When your component renders, `useRuleDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useRuleDetails({
 *   variables: {
 *      ruleDetailsInput: // value for 'ruleDetailsInput'
 *      alertsForRuleInput: // value for 'alertsForRuleInput'
 *   },
 * });
 */
export function useRuleDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<RuleDetails, RuleDetailsVariables>
) {
  return ApolloReactHooks.useQuery<RuleDetails, RuleDetailsVariables>(
    RuleDetailsDocument,
    baseOptions
  );
}
export function useRuleDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<RuleDetails, RuleDetailsVariables>
) {
  return ApolloReactHooks.useLazyQuery<RuleDetails, RuleDetailsVariables>(
    RuleDetailsDocument,
    baseOptions
  );
}
export type RuleDetailsHookResult = ReturnType<typeof useRuleDetails>;
export type RuleDetailsLazyQueryHookResult = ReturnType<typeof useRuleDetailsLazyQuery>;
export type RuleDetailsQueryResult = ApolloReactCommon.QueryResult<
  RuleDetails,
  RuleDetailsVariables
>;
