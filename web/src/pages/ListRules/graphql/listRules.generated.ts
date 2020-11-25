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

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListRulesVariables = {
  input?: Types.Maybe<Types.ListRulesInput>;
};

export type ListRules = {
  rules?: Types.Maybe<{
    rules?: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.RuleSummary,
            | 'lastModified'
            | 'logTypes'
            | 'severity'
            | 'id'
            | 'displayName'
            | 'threshold'
            | 'enabled'
            | 'outputIds'
          >
        >
      >
    >;
    paging?: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
  }>;
};

export const ListRulesDocument = gql`
  query ListRules($input: ListRulesInput) {
    rules(input: $input) {
      rules {
        lastModified
        logTypes
        severity
        id
        displayName
        threshold
        enabled
        outputIds
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
`;

/**
 * __useListRules__
 *
 * To run a query within a React component, call `useListRules` and pass it any options that fit your needs.
 * When your component renders, `useListRules` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListRules({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListRules(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListRules, ListRulesVariables>
) {
  return ApolloReactHooks.useQuery<ListRules, ListRulesVariables>(ListRulesDocument, baseOptions);
}
export function useListRulesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListRules, ListRulesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListRules, ListRulesVariables>(
    ListRulesDocument,
    baseOptions
  );
}
export type ListRulesHookResult = ReturnType<typeof useListRules>;
export type ListRulesLazyQueryHookResult = ReturnType<typeof useListRulesLazyQuery>;
export type ListRulesQueryResult = ApolloReactCommon.QueryResult<ListRules, ListRulesVariables>;
export function mockListRules({
  data,
  variables,
  errors,
}: {
  data: ListRules;
  variables?: ListRulesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListRulesDocument, variables },
    result: { data, errors },
  };
}
