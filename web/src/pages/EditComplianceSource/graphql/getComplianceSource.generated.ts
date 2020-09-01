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

import { ComplianceIntegrationDetails } from '../../../graphql/fragments/ComplianceIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
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
export function mockGetComplianceSource({
  data,
  variables,
  errors,
}: {
  data: GetComplianceSource;
  variables?: GetComplianceSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetComplianceSourceDocument, variables },
    result: { data, errors },
  };
}
