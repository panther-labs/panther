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

export type ListComplianceSourcesVariables = {};

export type ListComplianceSources = {
  listComplianceIntegrations: Array<ComplianceIntegrationDetails>;
};

export const ListComplianceSourcesDocument = gql`
  query ListComplianceSources {
    listComplianceIntegrations {
      ...ComplianceIntegrationDetails
    }
  }
  ${ComplianceIntegrationDetails}
`;

/**
 * __useListComplianceSources__
 *
 * To run a query within a React component, call `useListComplianceSources` and pass it any options that fit your needs.
 * When your component renders, `useListComplianceSources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListComplianceSources({
 *   variables: {
 *   },
 * });
 */
export function useListComplianceSources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListComplianceSources,
    ListComplianceSourcesVariables
  >
) {
  return ApolloReactHooks.useQuery<ListComplianceSources, ListComplianceSourcesVariables>(
    ListComplianceSourcesDocument,
    baseOptions
  );
}
export function useListComplianceSourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListComplianceSources,
    ListComplianceSourcesVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<ListComplianceSources, ListComplianceSourcesVariables>(
    ListComplianceSourcesDocument,
    baseOptions
  );
}
export type ListComplianceSourcesHookResult = ReturnType<typeof useListComplianceSources>;
export type ListComplianceSourcesLazyQueryHookResult = ReturnType<
  typeof useListComplianceSourcesLazyQuery
>;
export type ListComplianceSourcesQueryResult = ApolloReactCommon.QueryResult<
  ListComplianceSources,
  ListComplianceSourcesVariables
>;
export function mockListComplianceSources({
  data,
  variables,
  errors,
}: {
  data: ListComplianceSources;
  variables?: ListComplianceSourcesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListComplianceSourcesDocument, variables },
    result: { data, errors },
  };
}
