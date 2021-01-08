/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import { RuleBasic } from '../../../graphql/fragments/RuleBasic.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type RuleDetailsVariables = {
  input: Types.GetRuleInput;
};

export type RuleDetails = { rule?: Types.Maybe<RuleBasic> };

export const RuleDetailsDocument = gql`
  query RuleDetails($input: GetRuleInput!) {
    rule(input: $input) {
      ...RuleBasic
    }
  }
  ${RuleBasic}
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
 *      input: // value for 'input'
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
export function mockRuleDetails({
  data,
  variables,
  errors,
}: {
  data: RuleDetails;
  variables?: RuleDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: RuleDetailsDocument, variables },
    result: { data, errors },
  };
}
