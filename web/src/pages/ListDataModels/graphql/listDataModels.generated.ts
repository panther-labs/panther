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

import { DataModelFull } from '../../../graphql/fragments/DataModelFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListDataModelsVariables = {
  input: Types.ListDataModelsInput;
};

export type ListDataModels = {
  listDataModels: {
    models: Array<DataModelFull>;
    paging: Pick<Types.PagingData, 'totalPages' | 'thisPage' | 'totalItems'>;
  };
};

export const ListDataModelsDocument = gql`
  query ListDataModels($input: ListDataModelsInput!) {
    listDataModels(input: $input) {
      models {
        ...DataModelFull
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
  }
  ${DataModelFull}
`;

/**
 * __useListDataModels__
 *
 * To run a query within a React component, call `useListDataModels` and pass it any options that fit your needs.
 * When your component renders, `useListDataModels` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListDataModels({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useListDataModels(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListDataModels, ListDataModelsVariables>
) {
  return ApolloReactHooks.useQuery<ListDataModels, ListDataModelsVariables>(
    ListDataModelsDocument,
    baseOptions
  );
}
export function useListDataModelsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListDataModels, ListDataModelsVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListDataModels, ListDataModelsVariables>(
    ListDataModelsDocument,
    baseOptions
  );
}
export type ListDataModelsHookResult = ReturnType<typeof useListDataModels>;
export type ListDataModelsLazyQueryHookResult = ReturnType<typeof useListDataModelsLazyQuery>;
export type ListDataModelsQueryResult = ApolloReactCommon.QueryResult<
  ListDataModels,
  ListDataModelsVariables
>;
export function mockListDataModels({
  data,
  variables,
  errors,
}: {
  data: ListDataModels;
  variables?: ListDataModelsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: ListDataModelsDocument, variables },
    result: { data, errors },
  };
}
