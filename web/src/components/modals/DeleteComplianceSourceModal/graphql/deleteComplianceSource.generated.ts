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

import * as Types from '../../../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteComplianceSourceVariables = {
  id: Types.Scalars['ID'];
};

export type DeleteComplianceSource = Pick<Types.Mutation, 'deleteComplianceIntegration'>;

export const DeleteComplianceSourceDocument = gql`
  mutation DeleteComplianceSource($id: ID!) {
    deleteComplianceIntegration(id: $id)
  }
`;
export type DeleteComplianceSourceMutationFn = ApolloReactCommon.MutationFunction<
  DeleteComplianceSource,
  DeleteComplianceSourceVariables
>;

/**
 * __useDeleteComplianceSource__
 *
 * To run a mutation, you first call `useDeleteComplianceSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteComplianceSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteComplianceSource, { data, loading, error }] = useDeleteComplianceSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useDeleteComplianceSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    DeleteComplianceSource,
    DeleteComplianceSourceVariables
  >
) {
  return ApolloReactHooks.useMutation<DeleteComplianceSource, DeleteComplianceSourceVariables>(
    DeleteComplianceSourceDocument,
    baseOptions
  );
}
export type DeleteComplianceSourceHookResult = ReturnType<typeof useDeleteComplianceSource>;
export type DeleteComplianceSourceMutationResult = ApolloReactCommon.MutationResult<
  DeleteComplianceSource
>;
export type DeleteComplianceSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteComplianceSource,
  DeleteComplianceSourceVariables
>;
export function mockDeleteComplianceSource({
  data,
  variables,
  errors,
}: {
  data: DeleteComplianceSource;
  variables?: DeleteComplianceSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: DeleteComplianceSourceDocument, variables },
    result: { data, errors },
  };
}
