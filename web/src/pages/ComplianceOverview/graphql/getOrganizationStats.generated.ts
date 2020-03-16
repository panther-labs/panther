/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetOrganizationStatsVariables = {};

export type GetOrganizationStats = {
  organizationStats: Types.Maybe<{
    scannedResources: Types.Maybe<{
      byType: Types.Maybe<
        Array<
          Types.Maybe<
            Pick<Types.ScannedResourceStats, 'type'> & {
              count: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
            }
          >
        >
      >;
    }>;
    appliedPolicies: Types.Maybe<{
      info: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      low: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      medium: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      high: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      critical: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
    }>;
    topFailingPolicies: Types.Maybe<
      Array<Types.Maybe<Pick<Types.PolicySummary, 'id' | 'severity'>>>
    >;
    topFailingResources: Types.Maybe<Array<Types.Maybe<Pick<Types.ResourceSummary, 'id'>>>>;
  }>;
  integrations: Types.Maybe<Array<Pick<Types.Integration, 'integrationId'>>>;
};

export const GetOrganizationStatsDocument = gql`
  query GetOrganizationStats {
    organizationStats {
      scannedResources {
        byType {
          type
          count {
            fail
            pass
            error
          }
        }
      }
      appliedPolicies {
        info {
          error
          pass
          fail
        }
        low {
          error
          pass
          fail
        }
        medium {
          error
          pass
          fail
        }
        high {
          error
          pass
          fail
        }
        critical {
          error
          pass
          fail
        }
      }
      topFailingPolicies {
        id
        severity
      }
      topFailingResources {
        id
      }
    }
    integrations(input: { integrationType: "aws-scan" }) {
      integrationId
    }
  }
`;

/**
 * __useGetOrganizationStats__
 *
 * To run a query within a React component, call `useGetOrganizationStats` and pass it any options that fit your needs.
 * When your component renders, `useGetOrganizationStats` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetOrganizationStats({
 *   variables: {
 *   },
 * });
 */
export function useGetOrganizationStats(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GetOrganizationStats,
    GetOrganizationStatsVariables
  >
) {
  return ApolloReactHooks.useQuery<GetOrganizationStats, GetOrganizationStatsVariables>(
    GetOrganizationStatsDocument,
    baseOptions
  );
}
export function useGetOrganizationStatsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetOrganizationStats,
    GetOrganizationStatsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetOrganizationStats, GetOrganizationStatsVariables>(
    GetOrganizationStatsDocument,
    baseOptions
  );
}
export type GetOrganizationStatsHookResult = ReturnType<typeof useGetOrganizationStats>;
export type GetOrganizationStatsLazyQueryHookResult = ReturnType<
  typeof useGetOrganizationStatsLazyQuery
>;
export type GetOrganizationStatsQueryResult = ApolloReactCommon.QueryResult<
  GetOrganizationStats,
  GetOrganizationStatsVariables
>;
