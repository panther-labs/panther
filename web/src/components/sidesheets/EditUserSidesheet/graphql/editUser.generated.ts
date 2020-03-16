/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type EditUserVariables = {
  input: Types.UpdateUserInput;
};

export type EditUser = Pick<Types.Mutation, 'updateUser'>;

export const EditUserDocument = gql`
  mutation EditUser($input: UpdateUserInput!) {
    updateUser(input: $input)
  }
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
