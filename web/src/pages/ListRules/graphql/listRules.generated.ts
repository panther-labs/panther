/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListRulesVariables = {
  input?: Types.Maybe<Types.ListRulesInput>;
};

export type ListRules = {
  rules: Types.Maybe<{
    rules: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.RuleSummary,
            'lastModified' | 'logTypes' | 'severity' | 'id' | 'displayName' | 'enabled'
          >
        >
      >
    >;
    paging: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
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
        enabled
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
