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

import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type LoadAllSchemaEntitiesVariables = {};

export type LoadAllSchemaEntities = {
  listLogDatabases: Array<
    Pick<Types.LogDatabase, 'name'> & {
      tables: Array<
        Pick<Types.LogDatabaseTable, 'name'> & {
          columns: Array<Pick<Types.LogDatabaseTableColumn, 'name' | 'type'>>;
        }
      >;
    }
  >;
};

export const LoadAllSchemaEntitiesDocument = gql`
  query LoadAllSchemaEntities {
    listLogDatabases {
      name
      tables {
        name
        columns {
          name
          type
        }
      }
    }
  }
`;

/**
 * __useLoadAllSchemaEntities__
 *
 * To run a query within a React component, call `useLoadAllSchemaEntities` and pass it any options that fit your needs.
 * When your component renders, `useLoadAllSchemaEntities` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useLoadAllSchemaEntities({
 *   variables: {
 *   },
 * });
 */
export function useLoadAllSchemaEntities(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    LoadAllSchemaEntities,
    LoadAllSchemaEntitiesVariables
  >
) {
  return ApolloReactHooks.useQuery<LoadAllSchemaEntities, LoadAllSchemaEntitiesVariables>(
    LoadAllSchemaEntitiesDocument,
    baseOptions
  );
}
export function useLoadAllSchemaEntitiesLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    LoadAllSchemaEntities,
    LoadAllSchemaEntitiesVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<LoadAllSchemaEntities, LoadAllSchemaEntitiesVariables>(
    LoadAllSchemaEntitiesDocument,
    baseOptions
  );
}
export type LoadAllSchemaEntitiesHookResult = ReturnType<typeof useLoadAllSchemaEntities>;
export type LoadAllSchemaEntitiesLazyQueryHookResult = ReturnType<
  typeof useLoadAllSchemaEntitiesLazyQuery
>;
export type LoadAllSchemaEntitiesQueryResult = ApolloReactCommon.QueryResult<
  LoadAllSchemaEntities,
  LoadAllSchemaEntitiesVariables
>;
