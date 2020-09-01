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

import * as Types from '../../../../../../__generated__/schema';

import { DestinationFull } from '../../../../../graphql/fragments/DestinationFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetDestinationDetailsVariables = {
  id: Types.Scalars['ID'];
};

export type GetDestinationDetails = { destination?: Types.Maybe<DestinationFull> };

export const GetDestinationDetailsDocument = gql`
  query GetDestinationDetails($id: ID!) {
    destination(id: $id) {
      ...DestinationFull
    }
  }
  ${DestinationFull}
`;

/**
 * __useGetDestinationDetails__
 *
 * To run a query within a React component, call `useGetDestinationDetails` and pass it any options that fit your needs.
 * When your component renders, `useGetDestinationDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetDestinationDetails({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useGetDestinationDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GetDestinationDetails,
    GetDestinationDetailsVariables
  >
) {
  return ApolloReactHooks.useQuery<GetDestinationDetails, GetDestinationDetailsVariables>(
    GetDestinationDetailsDocument,
    baseOptions
  );
}
export function useGetDestinationDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetDestinationDetails,
    GetDestinationDetailsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetDestinationDetails, GetDestinationDetailsVariables>(
    GetDestinationDetailsDocument,
    baseOptions
  );
}
export type GetDestinationDetailsHookResult = ReturnType<typeof useGetDestinationDetails>;
export type GetDestinationDetailsLazyQueryHookResult = ReturnType<
  typeof useGetDestinationDetailsLazyQuery
>;
export type GetDestinationDetailsQueryResult = ApolloReactCommon.QueryResult<
  GetDestinationDetails,
  GetDestinationDetailsVariables
>;
export function mockGetDestinationDetails({
  data,
  variables,
  errors,
}: {
  data: GetDestinationDetails;
  variables?: GetDestinationDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetDestinationDetailsDocument, variables },
    result: { data, errors },
  };
}
