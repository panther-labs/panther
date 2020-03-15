/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteUserVariables = {
  id: Types.Scalars['ID'];
};

export type DeleteUser = Pick<Types.Mutation, 'deleteUser'>;

export const DeleteUserDocument = gql`
  mutation DeleteUser($id: ID!) {
    deleteUser(id: $id)
  }
`;
export type DeleteUserMutationFn = ApolloReactCommon.MutationFunction<
  DeleteUser,
  DeleteUserVariables
>;

/**
 * __useDeleteUser__
 *
 * To run a mutation, you first call `useDeleteUser` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteUser` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteUser, { data, loading, error }] = useDeleteUser({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useDeleteUser(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteUser, DeleteUserVariables>
) {
  return ApolloReactHooks.useMutation<DeleteUser, DeleteUserVariables>(
    DeleteUserDocument,
    baseOptions
  );
}
export type DeleteUserHookResult = ReturnType<typeof useDeleteUser>;
export type DeleteUserMutationResult = ApolloReactCommon.MutationResult<DeleteUser>;
export type DeleteUserMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteUser,
  DeleteUserVariables
>;
