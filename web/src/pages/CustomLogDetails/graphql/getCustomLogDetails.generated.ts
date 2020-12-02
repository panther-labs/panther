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

import { CustomLogFull } from '../../../graphql/fragments/CustomLogFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetCustomLogDetailsVariables = {
  input: Types.GetCustomLogInput;
};

export type GetCustomLogDetails = {
  getCustomLog: {
    error?: Types.Maybe<Pick<Types.Error, 'code' | 'message'>>;
    record?: Types.Maybe<CustomLogFull>;
  };
};

export const GetCustomLogDetailsDocument = gql`
  query GetCustomLogDetails($input: GetCustomLogInput!) {
    getCustomLog(input: $input) {
      error {
        code
        message
      }
      record {
        ...CustomLogFull
      }
    }
  }
  ${CustomLogFull}
`;

/**
 * __useGetCustomLogDetails__
 *
 * To run a query within a React component, call `useGetCustomLogDetails` and pass it any options that fit your needs.
 * When your component renders, `useGetCustomLogDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetCustomLogDetails({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetCustomLogDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetCustomLogDetails, GetCustomLogDetailsVariables>
) {
  return ApolloReactHooks.useQuery<GetCustomLogDetails, GetCustomLogDetailsVariables>(
    GetCustomLogDetailsDocument,
    baseOptions
  );
}
export function useGetCustomLogDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetCustomLogDetails,
    GetCustomLogDetailsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetCustomLogDetails, GetCustomLogDetailsVariables>(
    GetCustomLogDetailsDocument,
    baseOptions
  );
}
export type GetCustomLogDetailsHookResult = ReturnType<typeof useGetCustomLogDetails>;
export type GetCustomLogDetailsLazyQueryHookResult = ReturnType<
  typeof useGetCustomLogDetailsLazyQuery
>;
export type GetCustomLogDetailsQueryResult = ApolloReactCommon.QueryResult<
  GetCustomLogDetails,
  GetCustomLogDetailsVariables
>;
export function mockGetCustomLogDetails({
  data,
  variables,
  errors,
}: {
  data: GetCustomLogDetails;
  variables?: GetCustomLogDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetCustomLogDetailsDocument, variables },
    result: { data, errors },
  };
}
