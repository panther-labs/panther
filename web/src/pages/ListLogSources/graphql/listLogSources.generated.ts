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

import { S3LogIntegrationDetails } from '../../../graphql/fragments/S3LogIntegrationDetails.generated';
import { SqsLogSourceIntegrationDetails } from '../../../graphql/fragments/SqsLogSourceIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListLogSourcesVariables = {};

export type ListLogSources = {
  listLogIntegrations: Array<S3LogIntegrationDetails | SqsLogSourceIntegrationDetails>;
};

export const ListLogSourcesDocument = gql`
  query ListLogSources {
    listLogIntegrations {
      ... on S3LogIntegration {
        ...S3LogIntegrationDetails
      }
      ... on SqsLogSourceIntegration {
        ...SqsLogSourceIntegrationDetails
      }
    }
  }
  ${S3LogIntegrationDetails}
  ${SqsLogSourceIntegrationDetails}
`;

/**
 * __useListLogSources__
 *
 * To run a query within a React component, call `useListLogSources` and pass it any options that fit your needs.
 * When your component renders, `useListLogSources` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListLogSources({
 *   variables: {
 *   },
 * });
 */
export function useListLogSources(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListLogSources, ListLogSourcesVariables>
) {
  return ApolloReactHooks.useQuery<ListLogSources, ListLogSourcesVariables>(
    ListLogSourcesDocument,
    baseOptions
  );
}
export function useListLogSourcesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListLogSources, ListLogSourcesVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListLogSources, ListLogSourcesVariables>(
    ListLogSourcesDocument,
    baseOptions
  );
}
export type ListLogSourcesHookResult = ReturnType<typeof useListLogSources>;
export type ListLogSourcesLazyQueryHookResult = ReturnType<typeof useListLogSourcesLazyQuery>;
export type ListLogSourcesQueryResult = ApolloReactCommon.QueryResult<
  ListLogSources,
  ListLogSourcesVariables
>;
export function mockListLogSources({
  data,
  variables,
  errors,
}: {
  data: ListLogSources;
  variables?: ListLogSourcesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListLogSourcesDocument, variables },
    result: { data, errors },
  };
}
