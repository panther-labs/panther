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

import { PolicySummary } from '../../../graphql/fragments/PolicySummary.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListPoliciesVariables = {
  input?: Types.Maybe<Types.ListPoliciesInput>;
};

export type ListPolicies = {
  policies?: Types.Maybe<{
    policies: Array<PolicySummary>;
    paging?: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
  }>;
};

export const ListPoliciesDocument = gql`
  query ListPolicies($input: ListPoliciesInput) {
    policies(input: $input) {
      policies {
        ...PolicySummary
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
  ${PolicySummary}
`;

/**
 * __useListPolicies__
 *
 * To run a query within a React component, call `useListPolicies` and pass it any options that fit your needs.
 * When your component renders, `useListPolicies` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListPolicies({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListPolicies(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListPolicies, ListPoliciesVariables>
) {
  return ApolloReactHooks.useQuery<ListPolicies, ListPoliciesVariables>(
    ListPoliciesDocument,
    baseOptions
  );
}
export function useListPoliciesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListPolicies, ListPoliciesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListPolicies, ListPoliciesVariables>(
    ListPoliciesDocument,
    baseOptions
  );
}
export type ListPoliciesHookResult = ReturnType<typeof useListPolicies>;
export type ListPoliciesLazyQueryHookResult = ReturnType<typeof useListPoliciesLazyQuery>;
export type ListPoliciesQueryResult = ApolloReactCommon.QueryResult<
  ListPolicies,
  ListPoliciesVariables
>;
export function mockListPolicies({
  data,
  variables,
  errors,
}: {
  data: ListPolicies;
  variables?: ListPoliciesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListPoliciesDocument, variables },
    result: { data, errors },
  };
}
