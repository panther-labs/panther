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

import * as Types from '../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListComplianceSourceNamesVariables = {};

export type ListComplianceSourceNames = {
  listComplianceIntegrations: Array<
    Pick<Types.ComplianceIntegration, 'integrationLabel' | 'integrationId'>
  >;
};

export const ListComplianceSourceNamesDocument = gql`
  query ListComplianceSourceNames {
    listComplianceIntegrations {
      integrationLabel
      integrationId
    }
  }
`;

/**
 * __useListComplianceSourceNames__
 *
 * To run a query within a React component, call `useListComplianceSourceNames` and pass it any options that fit your needs.
 * When your component renders, `useListComplianceSourceNames` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListComplianceSourceNames({
 *   variables: {
 *   },
 * });
 */
export function useListComplianceSourceNames(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    ListComplianceSourceNames,
    ListComplianceSourceNamesVariables
  >
) {
  return ApolloReactHooks.useQuery<ListComplianceSourceNames, ListComplianceSourceNamesVariables>(
    ListComplianceSourceNamesDocument,
    baseOptions
  );
}
export function useListComplianceSourceNamesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    ListComplianceSourceNames,
    ListComplianceSourceNamesVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<
    ListComplianceSourceNames,
    ListComplianceSourceNamesVariables
  >(ListComplianceSourceNamesDocument, baseOptions);
}
export type ListComplianceSourceNamesHookResult = ReturnType<typeof useListComplianceSourceNames>;
export type ListComplianceSourceNamesLazyQueryHookResult = ReturnType<
  typeof useListComplianceSourceNamesLazyQuery
>;
export type ListComplianceSourceNamesQueryResult = ApolloReactCommon.QueryResult<
  ListComplianceSourceNames,
  ListComplianceSourceNamesVariables
>;
export function mockListComplianceSourceNames({
  data,
  variables,
  errors,
}: {
  data: ListComplianceSourceNames;
  variables?: ListComplianceSourceNamesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListComplianceSourceNamesDocument, variables },
    result: { data, errors },
  };
}
