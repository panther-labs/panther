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

import { UserDetails } from '../../../../graphql/fragments/UserDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type EditUserVariables = {
  input: Types.UpdateUserInput;
};

export type EditUser = { updateUser: UserDetails };

export const EditUserDocument = gql`
  mutation EditUser($input: UpdateUserInput!) {
    updateUser(input: $input) {
      ...UserDetails
    }
  }
  ${UserDetails}
`;
export type EditUserMutationFn = ApolloReactCommon.MutationFunction<EditUser, EditUserVariables>;

/**
 * __useEditUser__
 *
 * To run a mutation, you first call `useEditUser` within a React component and pass it any options that fit your needs.
 * When your component renders, `useEditUser` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [editUser, { data, loading, error }] = useEditUser({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useEditUser(
  baseOptions?: ApolloReactHooks.MutationHookOptions<EditUser, EditUserVariables>
) {
  return ApolloReactHooks.useMutation<EditUser, EditUserVariables>(EditUserDocument, baseOptions);
}
export type EditUserHookResult = ReturnType<typeof useEditUser>;
export type EditUserMutationResult = ApolloReactCommon.MutationResult<EditUser>;
export type EditUserMutationOptions = ApolloReactCommon.BaseMutationOptions<
  EditUser,
  EditUserVariables
>;
export function mockEditUser({
  data,
  variables,
  errors,
}: {
  data: EditUser;
  variables?: EditUserVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: EditUserDocument, variables },
    result: { data, errors },
  };
}
