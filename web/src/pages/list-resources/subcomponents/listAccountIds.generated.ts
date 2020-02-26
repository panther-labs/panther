/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListAccountIdsQueryVariables = {};

export type ListAccountIdsQuery = {
  integrations: Types.Maybe<Array<Pick<Types.Integration, 'integrationLabel' | 'integrationId'>>>;
};

export const ListAccountIdsDocument = gql`
  query ListAccountIds {
    integrations(input: { integrationType: "aws-scan" }) {
      integrationLabel
      integrationId
    }
  }
`;

/**
 * __useListAccountIdsQuery__
 *
 * To run a query within a React component, call `useListAccountIdsQuery` and pass it any options that fit your needs.
 * When your component renders, `useListAccountIdsQuery` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListAccountIdsQuery({
 *   variables: {
 *   },
 * });
 */
export function useListAccountIdsQuery(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListAccountIdsQuery, ListAccountIdsQueryVariables>
) {
  return ApolloReactHooks.useQuery<ListAccountIdsQuery, ListAccountIdsQueryVariables>(
    ListAccountIdsDocument,
    baseOptions
  );
}
export function useListAccountIdsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListAccountIdsQuery,
    ListAccountIdsQueryVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListAccountIdsQuery, ListAccountIdsQueryVariables>(
    ListAccountIdsDocument,
    baseOptions
  );
}
export type ListAccountIdsQueryHookResult = ReturnType<typeof useListAccountIdsQuery>;
export type ListAccountIdsLazyQueryHookResult = ReturnType<typeof useListAccountIdsLazyQuery>;
export type ListAccountIdsQueryResult = ApolloReactCommon.QueryResult<
  ListAccountIdsQuery,
  ListAccountIdsQueryVariables
>;
