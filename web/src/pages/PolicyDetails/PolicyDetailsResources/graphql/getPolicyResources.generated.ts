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

import * as Types from '../../../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetPolicyResourcesVariables = {
  resourcesForPolicyInput: Types.ResourcesForPolicyInput;
};

export type GetPolicyResources = {
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

export const GetPolicyResourcesDocument = gql`
  query GetPolicyResources($resourcesForPolicyInput: ResourcesForPolicyInput!) {
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
`;

/**
 * __useGetPolicyResources__
 *
 * To run a query within a React component, call `useGetPolicyResources` and pass it any options that fit your needs.
 * When your component renders, `useGetPolicyResources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetPolicyResources({
 *   variables: {
 *      resourcesForPolicyInput: // value for 'resourcesForPolicyInput'
 *   },
 * });
 */
export function useGetPolicyResources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetPolicyResources, GetPolicyResourcesVariables>
) {
  return ApolloReactHooks.useQuery<GetPolicyResources, GetPolicyResourcesVariables>(
    GetPolicyResourcesDocument,
    baseOptions
  );
}
export function useGetPolicyResourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetPolicyResources,
    GetPolicyResourcesVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetPolicyResources, GetPolicyResourcesVariables>(
    GetPolicyResourcesDocument,
    baseOptions
  );
}
export type GetPolicyResourcesHookResult = ReturnType<typeof useGetPolicyResources>;
export type GetPolicyResourcesLazyQueryHookResult = ReturnType<
  typeof useGetPolicyResourcesLazyQuery
>;
export type GetPolicyResourcesQueryResult = ApolloReactCommon.QueryResult<
  GetPolicyResources,
  GetPolicyResourcesVariables
>;
export function mockGetPolicyResources({
  data,
  variables,
  errors,
}: {
  data: GetPolicyResources;
  variables?: GetPolicyResourcesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetPolicyResourcesDocument, variables },
    result: { data, errors },
  };
}
