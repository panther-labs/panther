/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListResourcesVariables = {
  input?: Types.Maybe<Types.ListResourcesInput>;
};

export type ListResources = {
  resources: Types.Maybe<{
    resources: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.ResourceSummary,
            'lastModified' | 'type' | 'integrationId' | 'complianceStatus' | 'id'
          >
        >
      >
    >;
    paging: Types.Maybe<Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>>;
  }>;
  integrations: Types.Maybe<Array<Pick<Types.Integration, 'integrationLabel' | 'integrationId'>>>;
};

export const ListResourcesDocument = gql`
  query ListResources($input: ListResourcesInput) {
    resources(input: $input) {
      resources {
        lastModified
        type
        integrationId
        complianceStatus
        id
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
    integrations(input: { integrationType: "aws-scan" }) {
      integrationLabel
      integrationId
    }
  }
`;

/**
 * __useListResources__
 *
 * To run a query within a React component, call `useListResources` and pass it any options that fit your needs.
 * When your component renders, `useListResources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListResources({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListResources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListResources, ListResourcesVariables>
) {
  return ApolloReactHooks.useQuery<ListResources, ListResourcesVariables>(
    ListResourcesDocument,
    baseOptions
  );
}
export function useListResourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListResources, ListResourcesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListResources, ListResourcesVariables>(
    ListResourcesDocument,
    baseOptions
  );
}
export type ListResourcesHookResult = ReturnType<typeof useListResources>;
export type ListResourcesLazyQueryHookResult = ReturnType<typeof useListResourcesLazyQuery>;
export type ListResourcesQueryResult = ApolloReactCommon.QueryResult<
  ListResources,
  ListResourcesVariables
>;
