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

import { PackDetails } from '../../../graphql/fragments/PackDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListPacksVariables = {
  input: Types.ListPacksInput;
};

export type ListPacks = {
  listPacks: {
    packs: Array<PackDetails>;
    paging: Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>;
  };
};

export const ListPacksDocument = gql`
  query ListPacks($input: ListPacksInput!) {
    listPacks(input: $input) {
      packs {
        ...PackDetails
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
  ${PackDetails}
`;

/**
 * __useListPacks__
 *
 * To run a query within a React component, call `useListPacks` and pass it any options that fit your needs.
 * When your component renders, `useListPacks` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListPacks({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListPacks(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListPacks, ListPacksVariables>
) {
  return ApolloReactHooks.useQuery<ListPacks, ListPacksVariables>(ListPacksDocument, baseOptions);
}
export function useListPacksLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListPacks, ListPacksVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListPacks, ListPacksVariables>(
    ListPacksDocument,
    baseOptions
  );
}
export type ListPacksHookResult = ReturnType<typeof useListPacks>;
export type ListPacksLazyQueryHookResult = ReturnType<typeof useListPacksLazyQuery>;
export type ListPacksQueryResult = ApolloReactCommon.QueryResult<ListPacks, ListPacksVariables>;
export function mockListPacks({
  data,
  variables,
  errors,
}: {
  data: ListPacks;
  variables?: ListPacksVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListPacksDocument, variables },
    result: { data, errors },
  };
}
