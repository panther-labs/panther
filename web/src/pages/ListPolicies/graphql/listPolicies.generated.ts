/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListPoliciesVariables = {
  input?: Types.Maybe<Types.ListPoliciesInput>;
};

export type ListPolicies = {
  policies: Types.Maybe<{
    policies: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.PolicySummary,
            | 'complianceStatus'
            | 'lastModified'
            | 'resourceTypes'
            | 'severity'
            | 'id'
            | 'displayName'
            | 'enabled'
          >
        >
      >
    >;
    paging: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
  }>;
};

export const ListPoliciesDocument = gql`
  query ListPolicies($input: ListPoliciesInput) {
    policies(input: $input) {
      policies {
        complianceStatus
        lastModified
        resourceTypes
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
