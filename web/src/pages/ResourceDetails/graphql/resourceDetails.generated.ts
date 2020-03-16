/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ResourceDetailsVariables = {
  resourceDetailsInput: Types.GetResourceInput;
  policiesForResourceInput?: Types.Maybe<Types.PoliciesForResourceInput>;
};

export type ResourceDetails = {
  resource: Types.Maybe<
    Pick<
      Types.ResourceDetails,
      | 'lastModified'
      | 'type'
      | 'integrationId'
      | 'integrationType'
      | 'complianceStatus'
      | 'id'
      | 'attributes'
    >
  >;
  policiesForResource: Types.Maybe<{
    items: Types.Maybe<
      Array<
        Types.Maybe<
          Pick<
            Types.ComplianceItem,
            'errorMessage' | 'policyId' | 'resourceId' | 'policySeverity' | 'status' | 'suppressed'
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
  integrations: Types.Maybe<Array<Pick<Types.Integration, 'integrationLabel' | 'integrationId'>>>;
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
      integrationType
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
    integrations(input: { integrationType: "aws-scan" }) {
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
