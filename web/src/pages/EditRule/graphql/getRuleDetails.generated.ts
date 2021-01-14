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

import { RuleDetails } from '../../../graphql/fragments/RuleDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetRuleDetailsVariables = {
  input: Types.GetRuleInput;
};

export type GetRuleDetails = { rule?: Types.Maybe<RuleDetails> };

export const GetRuleDetailsDocument = gql`
  query GetRuleDetails($input: GetRuleInput!) {
    rule(input: $input) {
      ...RuleDetails
    }
  }
  ${RuleDetails}
`;

/**
 * __useGetRuleDetails__
 *
 * To run a query within a React component, call `useGetRuleDetails` and pass it any options that fit your needs.
 * When your component renders, `useGetRuleDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetRuleDetails({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetRuleDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetRuleDetails, GetRuleDetailsVariables>
) {
  return ApolloReactHooks.useQuery<GetRuleDetails, GetRuleDetailsVariables>(
    GetRuleDetailsDocument,
    baseOptions
  );
}
export function useGetRuleDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetRuleDetails, GetRuleDetailsVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetRuleDetails, GetRuleDetailsVariables>(
    GetRuleDetailsDocument,
    baseOptions
  );
}
export type GetRuleDetailsHookResult = ReturnType<typeof useGetRuleDetails>;
export type GetRuleDetailsLazyQueryHookResult = ReturnType<typeof useGetRuleDetailsLazyQuery>;
export type GetRuleDetailsQueryResult = ApolloReactCommon.QueryResult<
  GetRuleDetails,
  GetRuleDetailsVariables
>;
export function mockGetRuleDetails({
  data,
  variables,
  errors,
}: {
  data: GetRuleDetails;
  variables?: GetRuleDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetRuleDetailsDocument, variables },
    result: { data, errors },
  };
}
