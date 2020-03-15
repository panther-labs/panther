/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListRemediationsVariables = {};

export type ListRemediations = Pick<Types.Query, 'remediations'>;

export const ListRemediationsDocument = gql`
  query ListRemediations {
    remediations
  }
`;

/**
 * __useListRemediations__
 *
 * To run a query within a React component, call `useListRemediations` and pass it any options that fit your needs.
 * When your component renders, `useListRemediations` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListRemediations({
 *   variables: {
 *   },
 * });
 */
export function useListRemediations(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListRemediations, ListRemediationsVariables>
) {
  return ApolloReactHooks.useQuery<ListRemediations, ListRemediationsVariables>(
    ListRemediationsDocument,
    baseOptions
  );
}
export function useListRemediationsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListRemediations, ListRemediationsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListRemediations, ListRemediationsVariables>(
    ListRemediationsDocument,
    baseOptions
  );
}
export type ListRemediationsHookResult = ReturnType<typeof useListRemediations>;
export type ListRemediationsLazyQueryHookResult = ReturnType<typeof useListRemediationsLazyQuery>;
export type ListRemediationsQueryResult = ApolloReactCommon.QueryResult<
  ListRemediations,
  ListRemediationsVariables
>;
