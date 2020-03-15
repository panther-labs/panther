/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type PolicyDetailsVariables = {
  policyDetailsInput: Types.GetPolicyInput;
  resourcesForPolicyInput: Types.ResourcesForPolicyInput;
};

export type PolicyDetails = {
  policy: Types.Maybe<
    Pick<
      Types.PolicyDetails,
      | 'autoRemediationId'
      | 'autoRemediationParameters'
      | 'complianceStatus'
      | 'createdAt'
      | 'description'
      | 'displayName'
      | 'enabled'
      | 'suppressions'
      | 'id'
      | 'lastModified'
      | 'reference'
      | 'resourceTypes'
      | 'runbook'
      | 'severity'
      | 'tags'
    >
  >;
  resourcesForPolicy: Types.Maybe<{
    items: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.ComplianceItem,
            | 'errorMessage'
            | 'integrationId'
            | 'lastUpdated'
            | 'policyId'
            | 'resourceId'
            | 'status'
            | 'suppressed'
          >
        >
      >
    >;
    paging: Types.Maybe<Pick<Types.PagingData, 'totalItems' | 'totalPages' | 'thisPage'>>;
    totals: Types.Maybe<{
      active: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
      suppressed: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
    }>;
  }>;
  integrations: Types.Maybe<Array<Pick<Types.Integration, 'integrationId' | 'integrationLabel'>>>;
};

export const PolicyDetailsDocument = gql`
  query PolicyDetails(
    $policyDetailsInput: GetPolicyInput!
    $resourcesForPolicyInput: ResourcesForPolicyInput!
  ) {
    policy(input: $policyDetailsInput) {
      autoRemediationId
      autoRemediationParameters
      complianceStatus
      createdAt
      description
      displayName
      enabled
      suppressions
      id
      lastModified
      reference
      resourceTypes
      runbook
      severity
      tags
    }
    resourcesForPolicy(input: $resourcesForPolicyInput) {
      items {
        errorMessage
        integrationId
        lastUpdated
        policyId
        resourceId
        status
        suppressed
      }
      paging {
        totalItems
        totalPages
        thisPage
      }
      totals {
        active {
          fail
          pass
          error
        }
        suppressed {
          fail
          pass
          error
        }
      }
    }
    integrations(input: { integrationType: "aws-scan" }) {
      integrationId
      integrationLabel
    }
  }
`;

/**
 * __usePolicyDetails__
 *
 * To run a query within a React component, call `usePolicyDetails` and pass it any options that fit your needs.
 * When your component renders, `usePolicyDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = usePolicyDetails({
 *   variables: {
 *      policyDetailsInput: // value for 'policyDetailsInput'
 *      resourcesForPolicyInput: // value for 'resourcesForPolicyInput'
 *   },
 * });
 */
export function usePolicyDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<PolicyDetails, PolicyDetailsVariables>
) {
  return ApolloReactHooks.useQuery<PolicyDetails, PolicyDetailsVariables>(
    PolicyDetailsDocument,
    baseOptions
  );
}
export function usePolicyDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<PolicyDetails, PolicyDetailsVariables>
) {
  return ApolloReactHooks.useLazyQuery<PolicyDetails, PolicyDetailsVariables>(
    PolicyDetailsDocument,
    baseOptions
  );
}
export type PolicyDetailsHookResult = ReturnType<typeof usePolicyDetails>;
export type PolicyDetailsLazyQueryHookResult = ReturnType<typeof usePolicyDetailsLazyQuery>;
export type PolicyDetailsQueryResult = ApolloReactCommon.QueryResult<
  PolicyDetails,
  PolicyDetailsVariables
>;
