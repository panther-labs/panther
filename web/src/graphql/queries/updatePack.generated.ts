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

import * as Types from '../../../__generated__/schema';

import { PackDetails } from '../fragments/PackDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdatePackVariables = {
  input: Types.UpdatePackInput;
};

export type UpdatePack = { updatePack: PackDetails };

export const UpdatePackDocument = gql`
  mutation UpdatePack($input: UpdatePackInput!) {
    updatePack(input: $input) {
      ...PackDetails
    }
  }
  ${PackDetails}
`;
export type UpdatePackMutationFn = ApolloReactCommon.MutationFunction<
  UpdatePack,
  UpdatePackVariables
>;

/**
 * __useUpdatePack__
 *
 * To run a mutation, you first call `useUpdatePack` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdatePack` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updatePack, { data, loading, error }] = useUpdatePack({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdatePack(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdatePack, UpdatePackVariables>
) {
  return ApolloReactHooks.useMutation<UpdatePack, UpdatePackVariables>(
    UpdatePackDocument,
    baseOptions
  );
}
export type UpdatePackHookResult = ReturnType<typeof useUpdatePack>;
export type UpdatePackMutationResult = ApolloReactCommon.MutationResult<UpdatePack>;
export type UpdatePackMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdatePack,
  UpdatePackVariables
>;
export function mockUpdatePack({
  data,
  variables,
  errors,
}: {
  data: UpdatePack;
  variables?: UpdatePackVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UpdatePackDocument, variables },
    result: { data, errors },
  };
}
