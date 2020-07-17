/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import * as Types from '../../../../__generated__/schema';

import { PolicyDetailsMain } from '../../../graphql/fragments/PolicyDetailsMain.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type PolicyDetailsVariables = {
  policyDetailsInput: Types.GetPolicyInput;
  resourcesForPolicyInput: Types.ResourcesForPolicyInput;
};

export type PolicyDetails = {
  policy?: Types.Maybe<PolicyDetailsMain>;
  resourcesForPolicy?: Types.Maybe<{
    items?: Types.Maybe<
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
    paging?: Types.Maybe<Pick<Types.PagingData, 'totalItems' | 'totalPages' | 'thisPage'>>;
    totals?: Types.Maybe<{
      active?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
      suppressed?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
    }>;
  }>;
  listComplianceIntegrations: Array<
    Pick<Types.ComplianceIntegration, 'integrationId' | 'integrationLabel'>
  >;
};

export const PolicyDetailsDocument = gql`
  query PolicyDetails(
    $policyDetailsInput: GetPolicyInput!
    $resourcesForPolicyInput: ResourcesForPolicyInput!
  ) {
    policy(input: $policyDetailsInput) {
      ...PolicyDetailsMain
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
    listComplianceIntegrations {
      integrationId
      integrationLabel
    }
  }
  ${PolicyDetailsMain}
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
export function mockPolicyDetails({
  data,
  variables,
  error,
}: {
  data: PolicyDetails;
  variables?: PolicyDetailsVariables;
  error?: Error;
}) {
  return {
    request: { query: PolicyDetailsDocument, variables },
    result: { data },
    error,
  };
}
