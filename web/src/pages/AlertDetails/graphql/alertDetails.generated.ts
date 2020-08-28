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

import { AlertDetailsFull } from '../../../graphql/fragments/AlertDetailsFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type AlertDetailsVariables = {
  input: Types.GetAlertInput;
};

export type AlertDetails = { alert?: Types.Maybe<AlertDetailsFull> };

export const AlertDetailsDocument = gql`
  query AlertDetails($input: GetAlertInput!) {
    alert(input: $input) {
      ...AlertDetailsFull
    }
  }
  ${AlertDetailsFull}
`;

/**
 * __useAlertDetails__
 *
 * To run a query within a React component, call `useAlertDetails` and pass it any options that fit your needs.
 * When your component renders, `useAlertDetails` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useAlertDetails({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useAlertDetails(
  baseOptions?: ApolloReactHooks.QueryHookOptions<AlertDetails, AlertDetailsVariables>
) {
  return ApolloReactHooks.useQuery<AlertDetails, AlertDetailsVariables>(
    AlertDetailsDocument,
    baseOptions
  );
}
export function useAlertDetailsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<AlertDetails, AlertDetailsVariables>
) {
  return ApolloReactHooks.useLazyQuery<AlertDetails, AlertDetailsVariables>(
    AlertDetailsDocument,
    baseOptions
  );
}
export type AlertDetailsHookResult = ReturnType<typeof useAlertDetails>;
export type AlertDetailsLazyQueryHookResult = ReturnType<typeof useAlertDetailsLazyQuery>;
export type AlertDetailsQueryResult = ApolloReactCommon.QueryResult<
  AlertDetails,
  AlertDetailsVariables
>;
export function mockAlertDetails({
  data,
  variables,
  errors,
}: {
  data: AlertDetails;
  variables?: AlertDetailsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: AlertDetailsDocument, variables },
    result: { data, errors },
  };
}
