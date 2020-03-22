/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../../__generated__/schema';

import { LogIntegrationDetails } from '../../../graphql/fragments/LogIntegrationDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetLogSourceVariables = {
  id: Types.Scalars['ID'];
};

export type GetLogSource = { getLogIntegration: LogIntegrationDetails };

export const GetLogSourceDocument = gql`
  query GetLogSource($id: ID!) {
    getLogIntegration(id: $id) {
      ...LogIntegrationDetails
    }
  }
  ${LogIntegrationDetails}
`;

/**
 * __useGetLogSource__
 *
 * To run a query within a React component, call `useGetLogSource` and pass it any options that fit your needs.
 * When your component renders, `useGetLogSource` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetLogSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useGetLogSource(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetLogSource, GetLogSourceVariables>
) {
  return ApolloReactHooks.useQuery<GetLogSource, GetLogSourceVariables>(
    GetLogSourceDocument,
    baseOptions
  );
}
export function useGetLogSourceLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetLogSource, GetLogSourceVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetLogSource, GetLogSourceVariables>(
    GetLogSourceDocument,
    baseOptions
  );
}
export type GetLogSourceHookResult = ReturnType<typeof useGetLogSource>;
export type GetLogSourceLazyQueryHookResult = ReturnType<typeof useGetLogSourceLazyQuery>;
export type GetLogSourceQueryResult = ApolloReactCommon.QueryResult<
  GetLogSource,
  GetLogSourceVariables
>;
