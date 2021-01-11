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

export type GetDataModelVariables = {
  id: Types.Scalars['ID'];
};

export type GetDataModel = { getDataModel?: Types.Maybe<DataModelFull> };

export const GetDataModelDocument = gql`
  query GetDataModel($id: ID!) {
    getDataModel(id: $id) {
      ...DataModelFull
    }
  }
  ${DataModelFull}
`;

/**
 * __useGetDataModel__
 *
 * To run a query within a React component, call `useGetDataModel` and pass it any options that fit your needs.
 * When your component renders, `useGetDataModel` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetDataModel({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useGetDataModel(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetDataModel, GetDataModelVariables>
) {
  return ApolloReactHooks.useQuery<GetDataModel, GetDataModelVariables>(
    GetDataModelDocument,
    baseOptions
  );
}
export function useGetDataModelLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetDataModel, GetDataModelVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetDataModel, GetDataModelVariables>(
    GetDataModelDocument,
    baseOptions
  );
}
export type GetDataModelHookResult = ReturnType<typeof useGetDataModel>;
export type GetDataModelLazyQueryHookResult = ReturnType<typeof useGetDataModelLazyQuery>;
export type GetDataModelQueryResult = ApolloReactCommon.QueryResult<
  GetDataModel,
  GetDataModelVariables
>;
export function mockGetDataModel({
  data,
  variables,
  errors,
}: {
  data: GetDataModel;
  variables?: GetDataModelVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetDataModelDocument, variables },
    result: { data, errors },
  };
}
