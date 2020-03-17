/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListComplianceSourcesVariables = {};

export type ListComplianceSources = {
  listComplianceIntegrations: Array<
    Types.Maybe<
      Pick<
        Types.ComplianceIntegration,
        | 'awsAccountId'
        | 'createdAtTime'
        | 'createdBy'
        | 'integrationId'
        | 'integrationLabel'
        | 'scanIntervalMins'
        | 'lastScanEndTime'
      >
    >
  >;
};

export const ListComplianceSourcesDocument = gql`
  query ListComplianceSources {
    listComplianceIntegrations {
      awsAccountId
      createdAtTime
      createdBy
      integrationId
      integrationLabel
      scanIntervalMins
      lastScanEndTime
    }
  }
`;

/**
 * __useListComplianceSources__
 *
 * To run a query within a React component, call `useListComplianceSources` and pass it any options that fit your needs.
 * When your component renders, `useListComplianceSources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListComplianceSources({
 *   variables: {
 *   },
 * });
 */
export function useListComplianceSources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListComplianceSources,
    ListComplianceSourcesVariables
  >
) {
  return ApolloReactHooks.useQuery<ListComplianceSources, ListComplianceSourcesVariables>(
    ListComplianceSourcesDocument,
    baseOptions
  );
}
export function useListComplianceSourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListComplianceSources,
    ListComplianceSourcesVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListComplianceSources, ListComplianceSourcesVariables>(
    ListComplianceSourcesDocument,
    baseOptions
  );
}
export type ListComplianceSourcesHookResult = ReturnType<typeof useListComplianceSources>;
export type ListComplianceSourcesLazyQueryHookResult = ReturnType<
  typeof useListComplianceSourcesLazyQuery
>;
export type ListComplianceSourcesQueryResult = ApolloReactCommon.QueryResult<
  ListComplianceSources,
  ListComplianceSourcesVariables
>;
