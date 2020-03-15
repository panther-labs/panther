/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListAccountIdsVariables = {};

export type ListAccountIds = {
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
 * __useListAccountIds__
 *
 * To run a query within a React component, call `useListAccountIds` and pass it any options that fit your needs.
 * When your component renders, `useListAccountIds` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListAccountIds({
 *   variables: {
 *   },
 * });
 */
export function useListAccountIds(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListAccountIds, ListAccountIdsVariables>
) {
  return ApolloReactHooks.useQuery<ListAccountIds, ListAccountIdsVariables>(
    ListAccountIdsDocument,
    baseOptions
  );
}
export function useListAccountIdsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListAccountIds, ListAccountIdsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListAccountIds, ListAccountIdsVariables>(
    ListAccountIdsDocument,
    baseOptions
  );
}
export type ListAccountIdsHookResult = ReturnType<typeof useListAccountIds>;
export type ListAccountIdsLazyQueryHookResult = ReturnType<typeof useListAccountIdsLazyQuery>;
export type ListAccountIdsQueryResult = ApolloReactCommon.QueryResult<
  ListAccountIds,
  ListAccountIdsVariables
>;
