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

export type ListAlertsForRuleVariables = {
  input: Types.ListAlertsInput;
};

export type ListAlertsForRule = {
  alerts?: Types.Maybe<
    Pick<Types.ListAlertsResponse, 'lastEvaluatedKey'> & {
      alertSummaries: Array<Types.Maybe<AlertSummaryFull>>;
    }
  >;
};

export const ListAlertsForRuleDocument = gql`
  query ListAlertsForRule($input: ListAlertsInput!) {
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
 * __useListAlertsForRule__
 *
 * To run a query within a React component, call `useListAlertsForRule` and pass it any options that fit your needs.
 * When your component renders, `useListAlertsForRule` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListAlertsForRule({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListAlertsForRule(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListAlertsForRule, ListAlertsForRuleVariables>
) {
  return ApolloReactHooks.useQuery<ListAlertsForRule, ListAlertsForRuleVariables>(
    ListAlertsForRuleDocument,
    baseOptions
  );
}
export function useListAlertsForRuleLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListAlertsForRule, ListAlertsForRuleVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListAlertsForRule, ListAlertsForRuleVariables>(
    ListAlertsForRuleDocument,
    baseOptions
  );
}
export type ListAlertsForRuleHookResult = ReturnType<typeof useListAlertsForRule>;
export type ListAlertsForRuleLazyQueryHookResult = ReturnType<typeof useListAlertsForRuleLazyQuery>;
export type ListAlertsForRuleQueryResult = ApolloReactCommon.QueryResult<
  ListAlertsForRule,
  ListAlertsForRuleVariables
>;
export function mockListAlertsForRule({
  data,
  variables,
  errors,
}: {
  data: ListAlertsForRule;
  variables?: ListAlertsForRuleVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListAlertsForRuleDocument, variables },
    result: { data, errors },
  };
}
