/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type InviteUserVariables = {
  input: Types.InviteUserInput;
};

export type InviteUser = { inviteUser: Types.Maybe<Pick<Types.InviteUserResponse, 'id'>> };

export const InviteUserDocument = gql`
  mutation InviteUser($input: InviteUserInput!) {
    inviteUser(input: $input) {
      id
    }
  }
`;
export type InviteUserMutationFn = ApolloReactCommon.MutationFunction<
  InviteUser,
  InviteUserVariables
>;

/**
 * __useInviteUser__
 *
 * To run a mutation, you first call `useInviteUser` within a React component and pass it any options that fit your needs.
 * When your component renders, `useInviteUser` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [inviteUser, { data, loading, error }] = useInviteUser({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useInviteUser(
  baseOptions?: ApolloReactHooks.MutationHookOptions<InviteUser, InviteUserVariables>
) {
  return ApolloReactHooks.useMutation<InviteUser, InviteUserVariables>(
    InviteUserDocument,
    baseOptions
  );
}
export type InviteUserHookResult = ReturnType<typeof useInviteUser>;
export type InviteUserMutationResult = ApolloReactCommon.MutationResult<InviteUser>;
export type InviteUserMutationOptions = ApolloReactCommon.BaseMutationOptions<
  InviteUser,
  InviteUserVariables
>;
