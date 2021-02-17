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

import { AnalysisPackSummary } from '../../../graphql/fragments/AnalysisPackSummary.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListAnalysisPacksVariables = {
  input: Types.ListAnalysisPacksInput;
};

export type ListAnalysisPacks = {
  listAnalysisPacks: {
    packs: Array<AnalysisPackSummary>;
    paging: Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>;
  };
};

export const ListAnalysisPacksDocument = gql`
  query ListAnalysisPacks($input: ListAnalysisPacksInput!) {
    listAnalysisPacks(input: $input) {
      packs {
        ...AnalysisPackSummary
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
  ${AnalysisPackSummary}
`;

/**
 * __useListAnalysisPacks__
 *
 * To run a query within a React component, call `useListAnalysisPacks` and pass it any options that fit your needs.
 * When your component renders, `useListAnalysisPacks` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListAnalysisPacks({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListAnalysisPacks(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListAnalysisPacks, ListAnalysisPacksVariables>
) {
  return ApolloReactHooks.useQuery<ListAnalysisPacks, ListAnalysisPacksVariables>(
    ListAnalysisPacksDocument,
    baseOptions
  );
}
export function useListAnalysisPacksLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListAnalysisPacks, ListAnalysisPacksVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListAnalysisPacks, ListAnalysisPacksVariables>(
    ListAnalysisPacksDocument,
    baseOptions
  );
}
export type ListAnalysisPacksHookResult = ReturnType<typeof useListAnalysisPacks>;
export type ListAnalysisPacksLazyQueryHookResult = ReturnType<typeof useListAnalysisPacksLazyQuery>;
export type ListAnalysisPacksQueryResult = ApolloReactCommon.QueryResult<
  ListAnalysisPacks,
  ListAnalysisPacksVariables
>;
export function mockListAnalysisPacks({
  data,
  variables,
  errors,
}: {
  data: ListAnalysisPacks;
  variables?: ListAnalysisPacksVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListAnalysisPacksDocument, variables },
    result: { data, errors },
  };
}
