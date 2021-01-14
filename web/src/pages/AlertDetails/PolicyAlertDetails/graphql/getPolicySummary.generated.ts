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

import { PolicySummary } from '../../../../graphql/fragments/PolicySummary.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetPolicySummaryVariables = {
  input: Types.GetPolicyInput;
};

export type GetPolicySummary = { policy?: Types.Maybe<PolicySummary> };

export const GetPolicySummaryDocument = gql`
  query GetPolicySummary($input: GetPolicyInput!) {
    policy(input: $input) {
      ...PolicySummary
    }
  }
  ${PolicySummary}
`;

/**
 * __useGetPolicySummary__
 *
 * To run a query within a React component, call `useGetPolicySummary` and pass it any options that fit your needs.
 * When your component renders, `useGetPolicySummary` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetPolicySummary({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetPolicySummary(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetPolicySummary, GetPolicySummaryVariables>
) {
  return ApolloReactHooks.useQuery<GetPolicySummary, GetPolicySummaryVariables>(
    GetPolicySummaryDocument,
    baseOptions
  );
}
export function useGetPolicySummaryLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetPolicySummary, GetPolicySummaryVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetPolicySummary, GetPolicySummaryVariables>(
    GetPolicySummaryDocument,
    baseOptions
  );
}
export type GetPolicySummaryHookResult = ReturnType<typeof useGetPolicySummary>;
export type GetPolicySummaryLazyQueryHookResult = ReturnType<typeof useGetPolicySummaryLazyQuery>;
export type GetPolicySummaryQueryResult = ApolloReactCommon.QueryResult<
  GetPolicySummary,
  GetPolicySummaryVariables
>;
export function mockGetPolicySummary({
  data,
  variables,
  errors,
}: {
  data: GetPolicySummary;
  variables?: GetPolicySummaryVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetPolicySummaryDocument, variables },
    result: { data, errors },
  };
}
