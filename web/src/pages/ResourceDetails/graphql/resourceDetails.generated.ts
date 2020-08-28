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

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ResourceDetailsVariables = {
  resourceDetailsInput: Types.GetResourceInput;
  policiesForResourceInput?: Types.Maybe<Types.PoliciesForResourceInput>;
};

export type ResourceDetails = {
  resource?: Types.Maybe<
    Pick<
      Types.ResourceDetails,
      'lastModified' | 'type' | 'integrationId' | 'complianceStatus' | 'id' | 'attributes'
    >
  >;
  policiesForResource?: Types.Maybe<{
    items?: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.ComplianceItem,
            'errorMessage' | 'policyId' | 'resourceId' | 'policySeverity' | 'status' | 'suppressed'
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
    Pick<Types.ComplianceIntegration, 'integrationLabel' | 'integrationId'>
  >;
};

export const ResourceDetailsDocument = gql`
  query ResourceDetails(
    $resourceDetailsInput: GetResourceInput!
    $policiesForResourceInput: PoliciesForResourceInput
  ) {
    resource(input: $resourceDetailsInput) {
      lastModified
      type
      integrationId
      complianceStatus
      id
      attributes
    }
    policiesForResource(input: $policiesForResourceInput) {
      items {
        errorMessage
        policyId
        resourceId
        policySeverity
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
      integrationLabel
      integrationId
    }
  }
`;

/**
 * __useResourceDetails__
 *
 * To run a query within a React component, call `useResourceDetails` and pass it any options that fit your needs.
 * When your component renders, `useResourceDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useResourceDetails({
 *   variables: {
 *      resourceDetailsInput: // value for 'resourceDetailsInput'
 *      policiesForResourceInput: // value for 'policiesForResourceInput'
 *   },
 * });
 */
export function useResourceDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ResourceDetails, ResourceDetailsVariables>
) {
  return ApolloReactHooks.useQuery<ResourceDetails, ResourceDetailsVariables>(
    ResourceDetailsDocument,
    baseOptions
  );
}
export function useResourceDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ResourceDetails, ResourceDetailsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ResourceDetails, ResourceDetailsVariables>(
    ResourceDetailsDocument,
    baseOptions
  );
}
export type ResourceDetailsHookResult = ReturnType<typeof useResourceDetails>;
export type ResourceDetailsLazyQueryHookResult = ReturnType<typeof useResourceDetailsLazyQuery>;
export type ResourceDetailsQueryResult = ApolloReactCommon.QueryResult<
  ResourceDetails,
  ResourceDetailsVariables
>;
export function mockResourceDetails({
  data,
  variables,
  errors,
}: {
  data: ResourceDetails;
  variables?: ResourceDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ResourceDetailsDocument, variables },
    result: { data, errors },
  };
}
