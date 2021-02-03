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

import { PolicyDetails } from '../../../graphql/fragments/PolicyDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetPolicyDetailsVariables = {
  policyDetailsInput: Types.GetPolicyInput;
  resourcesForPolicyInput: Types.ResourcesForPolicyInput;
};

export type GetPolicyDetails = {
  policy?: Types.Maybe<PolicyDetails>;
  resourcesForPolicy?: Types.Maybe<{
    totals?: Types.Maybe<{
      active?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
      suppressed?: Types.Maybe<Pick<Types.ComplianceStatusCounts, 'fail' | 'pass' | 'error'>>;
    }>;
  }>;
};

export const GetPolicyDetailsDocument = gql`
  query GetPolicyDetails(
    $policyDetailsInput: GetPolicyInput!
    $resourcesForPolicyInput: ResourcesForPolicyInput!
  ) {
    policy(input: $policyDetailsInput) {
      ...PolicyDetails
    }
    resourcesForPolicy(input: $resourcesForPolicyInput) {
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
  }
  ${PolicyDetails}
`;

/**
 * __useGetPolicyDetails__
 *
 * To run a query within a React component, call `useGetPolicyDetails` and pass it any options that fit your needs.
 * When your component renders, `useGetPolicyDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetPolicyDetails({
 *   variables: {
 *      policyDetailsInput: // value for 'policyDetailsInput'
 *      resourcesForPolicyInput: // value for 'resourcesForPolicyInput'
 *   },
 * });
 */
export function useGetPolicyDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetPolicyDetails, GetPolicyDetailsVariables>
) {
  return ApolloReactHooks.useQuery<GetPolicyDetails, GetPolicyDetailsVariables>(
    GetPolicyDetailsDocument,
    baseOptions
  );
}
export function useGetPolicyDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetPolicyDetails, GetPolicyDetailsVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetPolicyDetails, GetPolicyDetailsVariables>(
    GetPolicyDetailsDocument,
    baseOptions
  );
}
export type GetPolicyDetailsHookResult = ReturnType<typeof useGetPolicyDetails>;
export type GetPolicyDetailsLazyQueryHookResult = ReturnType<typeof useGetPolicyDetailsLazyQuery>;
export type GetPolicyDetailsQueryResult = ApolloReactCommon.QueryResult<
  GetPolicyDetails,
  GetPolicyDetailsVariables
>;
export function mockGetPolicyDetails({
  data,
  variables,
  errors,
}: {
  data: GetPolicyDetails;
  variables?: GetPolicyDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetPolicyDetailsDocument, variables },
    result: { data, errors },
  };
}
