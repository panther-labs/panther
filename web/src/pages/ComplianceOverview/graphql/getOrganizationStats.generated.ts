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

export type GetOrganizationStatsVariables = {};

export type GetOrganizationStats = {
  organizationStats?: Types.Maybe<{
    scannedResources?: Types.Maybe<{
      byType?: Types.Maybe<
        Array<
          Types.Maybe<
            Pick<Types.ScannedResourceStats, 'type'> & {
              count?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
            }
          >
        >
      >;
    }>;
    appliedPolicies?: Types.Maybe<{
      info?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      low?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      medium?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      high?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
      critical?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'error' | 'pass' | 'fail'>>;
    }>;
    topFailingPolicies: Array<Pick<Types.Policy, 'id' | 'severity'>>;
    topFailingResources: Array<Pick<Types.ResourceSummary, 'id'>>;
  }>;
  listComplianceIntegrations: Array<Pick<Types.ComplianceIntegration, 'integrationId'>>;
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
    listComplianceIntegrations {
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
export function mockGetOrganizationStats({
  data,
  variables,
  errors,
}: {
  data: GetOrganizationStats;
  variables?: GetOrganizationStatsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetOrganizationStatsDocument, variables },
    result: { data, errors },
  };
}
