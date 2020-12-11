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

import { PolicyBasic } from '../../../graphql/fragments/PolicyBasic.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type PolicyTeaserVariables = {
  input: Types.GetPolicyInput;
};

export type PolicyTeaser = { policy?: Types.Maybe<PolicyBasic> };

export const PolicyTeaserDocument = gql`
  query PolicyTeaser($input: GetPolicyInput!) {
    policy(input: $input) {
      ...PolicyBasic
    }
  }
  ${PolicyBasic}
`;

/**
 * __usePolicyTeaser__
 *
 * To run a query within a React component, call `usePolicyTeaser` and pass it any options that fit your needs.
 * When your component renders, `usePolicyTeaser` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = usePolicyTeaser({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function usePolicyTeaser(
  baseOptions?: ApolloReactHooks.QueryHookOptions<PolicyTeaser, PolicyTeaserVariables>
) {
  return ApolloReactHooks.useQuery<PolicyTeaser, PolicyTeaserVariables>(
    PolicyTeaserDocument,
    baseOptions
  );
}
export function usePolicyTeaserLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<PolicyTeaser, PolicyTeaserVariables>
) {
  return ApolloReactHooks.useLazyQuery<PolicyTeaser, PolicyTeaserVariables>(
    PolicyTeaserDocument,
    baseOptions
  );
}
export type PolicyTeaserHookResult = ReturnType<typeof usePolicyTeaser>;
export type PolicyTeaserLazyQueryHookResult = ReturnType<typeof usePolicyTeaserLazyQuery>;
export type PolicyTeaserQueryResult = ApolloReactCommon.QueryResult<
  PolicyTeaser,
  PolicyTeaserVariables
>;
export function mockPolicyTeaser({
  data,
  variables,
  errors,
}: {
  data: PolicyTeaser;
  variables?: PolicyTeaserVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: PolicyTeaserDocument, variables },
    result: { data, errors },
  };
}
