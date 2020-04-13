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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../../../__generated__/schema';

import { UserDetails } from '../../../../graphql/fragments/UserDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ListUsersVariables = {};

export type ListUsers = { users: Array<UserDetails> };

export const ListUsersDocument = gql`
  query ListUsers {
    users {
      ...UserDetails
    }
  }
  ${UserDetails}
`;

/**
 * __useListUsers__
 *
 * To run a query within a React component, call `useListUsers` and pass it any options that fit your needs.
 * When your component renders, `useListUsers` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useListUsers({
 *   variables: {
 *   },
 * });
 */
export function useListUsers(
  baseOptions?: ApolloReactHooks.QueryHookOptions<ListUsers, ListUsersVariables>
) {
  return ApolloReactHooks.useQuery<ListUsers, ListUsersVariables>(ListUsersDocument, baseOptions);
}
export function useListUsersLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<ListUsers, ListUsersVariables>
) {
  return ApolloReactHooks.useLazyQuery<ListUsers, ListUsersVariables>(
    ListUsersDocument,
    baseOptions
  );
}
export type ListUsersHookResult = ReturnType<typeof useListUsers>;
export type ListUsersLazyQueryHookResult = ReturnType<typeof useListUsersLazyQuery>;
export type ListUsersQueryResult = ApolloReactCommon.QueryResult<ListUsers, ListUsersVariables>;
