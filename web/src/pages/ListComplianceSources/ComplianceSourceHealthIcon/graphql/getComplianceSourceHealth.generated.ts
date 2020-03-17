/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import { IntegrationItemHealthDetails } from '../../../../graphql/fragments/IntegrationItemHealthDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetComplianceSourceHealthVariables = {
  input: Types.GetComplianceIntegrationHealthInput;
};

export type GetComplianceSourceHealth = {
  getComplianceIntegrationHealth: {
    auditRoleStatus: IntegrationItemHealthDetails;
    cweRoleStatus: IntegrationItemHealthDetails;
    remediationRoleStatus: IntegrationItemHealthDetails;
  };
};

export const GetComplianceSourceHealthDocument = gql`
  query GetComplianceSourceHealth($input: GetComplianceIntegrationHealthInput!) {
    getComplianceIntegrationHealth(input: $input) {
      auditRoleStatus {
        ...IntegrationItemHealthDetails
      }
      cweRoleStatus {
        ...IntegrationItemHealthDetails
      }
      remediationRoleStatus {
        ...IntegrationItemHealthDetails
      }
    }
  }
  ${IntegrationItemHealthDetails}
`;

/**
 * __useGetComplianceSourceHealth__
 *
 * To run a query within a React component, call `useGetComplianceSourceHealth` and pass it any options that fit your needs.
 * When your component renders, `useGetComplianceSourceHealth` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetComplianceSourceHealth({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetComplianceSourceHealth(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GetComplianceSourceHealth,
    GetComplianceSourceHealthVariables
  >
) {
  return ApolloReactHooks.useQuery<GetComplianceSourceHealth, GetComplianceSourceHealthVariables>(
    GetComplianceSourceHealthDocument,
    baseOptions
  );
}
export function useGetComplianceSourceHealthLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetComplianceSourceHealth,
    GetComplianceSourceHealthVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<
    GetComplianceSourceHealth,
    GetComplianceSourceHealthVariables
  >(GetComplianceSourceHealthDocument, baseOptions);
}
export type GetComplianceSourceHealthHookResult = ReturnType<typeof useGetComplianceSourceHealth>;
export type GetComplianceSourceHealthLazyQueryHookResult = ReturnType<
  typeof useGetComplianceSourceHealthLazyQuery
>;
export type GetComplianceSourceHealthQueryResult = ApolloReactCommon.QueryResult<
  GetComplianceSourceHealth,
  GetComplianceSourceHealthVariables
>;
