/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import { ComplianceIntegrationDetails } from '../../../graphql/fragments/ComplianceIntegrationDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetComplianceSourceVariables = {
  id: Types.Scalars['ID'];
};

export type GetComplianceSource = { getComplianceIntegration: ComplianceIntegrationDetails };

export const GetComplianceSourceDocument = gql`
  query GetComplianceSource($id: ID!) {
    getComplianceIntegration(id: $id) {
      ...ComplianceIntegrationDetails
    }
  }
  ${ComplianceIntegrationDetails}
`;

/**
 * __useGetComplianceSource__
 *
 * To run a query within a React component, call `useGetComplianceSource` and pass it any options that fit your needs.
 * When your component renders, `useGetComplianceSource` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetComplianceSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useGetComplianceSource(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetComplianceSource, GetComplianceSourceVariables>
) {
  return ApolloReactHooks.useQuery<GetComplianceSource, GetComplianceSourceVariables>(
    GetComplianceSourceDocument,
    baseOptions
  );
}
export function useGetComplianceSourceLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetComplianceSource,
    GetComplianceSourceVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetComplianceSource, GetComplianceSourceVariables>(
    GetComplianceSourceDocument,
    baseOptions
  );
}
export type GetComplianceSourceHookResult = ReturnType<typeof useGetComplianceSource>;
export type GetComplianceSourceLazyQueryHookResult = ReturnType<
  typeof useGetComplianceSourceLazyQuery
>;
export type GetComplianceSourceQueryResult = ApolloReactCommon.QueryResult<
  GetComplianceSource,
  GetComplianceSourceVariables
>;
