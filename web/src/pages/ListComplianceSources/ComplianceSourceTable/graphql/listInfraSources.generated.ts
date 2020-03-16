/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListInfraSourcesVariables = {};

export type ListInfraSources = {
  integrations: Types.Maybe<
    Array<
      Pick<
        Types.Integration,
        | 'awsAccountId'
        | 'createdAtTime'
        | 'createdBy'
        | 'integrationId'
        | 'integrationLabel'
        | 'integrationType'
        | 'scanEnabled'
        | 'scanIntervalMins'
        | 'scanStatus'
        | 'lastScanEndTime'
      >
    >
  >;
};

export const ListInfraSourcesDocument = gql`
  query ListInfraSources {
    integrations(input: { integrationType: "aws-scan" }) {
      awsAccountId
      createdAtTime
      createdBy
      integrationId
      integrationLabel
      integrationType
      scanEnabled
      scanIntervalMins
      scanStatus
      lastScanEndTime
    }
  }
`;

/**
 * __useListInfraSources__
 *
 * To run a query within a React component, call `useListInfraSources` and pass it any options that fit your needs.
 * When your component renders, `useListInfraSources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListInfraSources({
 *   variables: {
 *   },
 * });
 */
export function useListInfraSources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListInfraSources, ListInfraSourcesVariables>
) {
  return ApolloReactHooks.useQuery<ListInfraSources, ListInfraSourcesVariables>(
    ListInfraSourcesDocument,
    baseOptions
  );
}
export function useListInfraSourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListInfraSources, ListInfraSourcesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListInfraSources, ListInfraSourcesVariables>(
    ListInfraSourcesDocument,
    baseOptions
  );
}
export type ListInfraSourcesHookResult = ReturnType<typeof useListInfraSources>;
export type ListInfraSourcesLazyQueryHookResult = ReturnType<typeof useListInfraSourcesLazyQuery>;
export type ListInfraSourcesQueryResult = ApolloReactCommon.QueryResult<
  ListInfraSources,
  ListInfraSourcesVariables
>;
