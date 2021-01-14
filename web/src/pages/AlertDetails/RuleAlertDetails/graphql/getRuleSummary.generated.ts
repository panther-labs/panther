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

import * as Types from '../../../../../__generated__/schema';

import { RuleSummary } from '../../../../graphql/fragments/RuleSummary.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetRuleSummaryVariables = {
  input: Types.GetRuleInput;
};

export type GetRuleSummary = { rule?: Types.Maybe<RuleSummary> };

export const GetRuleSummaryDocument = gql`
  query GetRuleSummary($input: GetRuleInput!) {
    rule(input: $input) {
      ...RuleSummary
    }
  }
  ${RuleSummary}
`;

/**
 * __useGetRuleSummary__
 *
 * To run a query within a React component, call `useGetRuleSummary` and pass it any options that fit your needs.
 * When your component renders, `useGetRuleSummary` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetRuleSummary({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetRuleSummary(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetRuleSummary, GetRuleSummaryVariables>
) {
  return ApolloReactHooks.useQuery<GetRuleSummary, GetRuleSummaryVariables>(
    GetRuleSummaryDocument,
    baseOptions
  );
}
export function useGetRuleSummaryLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetRuleSummary, GetRuleSummaryVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetRuleSummary, GetRuleSummaryVariables>(
    GetRuleSummaryDocument,
    baseOptions
  );
}
export type GetRuleSummaryHookResult = ReturnType<typeof useGetRuleSummary>;
export type GetRuleSummaryLazyQueryHookResult = ReturnType<typeof useGetRuleSummaryLazyQuery>;
export type GetRuleSummaryQueryResult = ApolloReactCommon.QueryResult<
  GetRuleSummary,
  GetRuleSummaryVariables
>;
export function mockGetRuleSummary({
  data,
  variables,
  errors,
}: {
  data: GetRuleSummary;
  variables?: GetRuleSummaryVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetRuleSummaryDocument, variables },
    result: { data, errors },
  };
}
