/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type ResetUserPasswordVariables = {
  id: Types.Scalars['ID'];
};

export type ResetUserPassword = Pick<Types.Mutation, 'resetUserPassword'>;

export const ResetUserPasswordDocument = gql`
  mutation ResetUserPassword($id: ID!) {
    resetUserPassword(id: $id)
  }
`;
export type ResetUserPasswordMutationFn = ApolloReactCommon.MutationFunction<
  ResetUserPassword,
  ResetUserPasswordVariables
>;

/**
 * __useResetUserPassword__
 *
 * To run a mutation, you first call `useResetUserPassword` within a React component and pass it any options that fit your needs.
 * When your component renders, `useResetUserPassword` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [resetUserPassword, { data, loading, error }] = useResetUserPassword({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useResetUserPassword(
  baseOptions?: ApolloReactHooks.MutationHookOptions<ResetUserPassword, ResetUserPasswordVariables>
) {
  return ApolloReactHooks.useMutation<ResetUserPassword, ResetUserPasswordVariables>(
    ResetUserPasswordDocument,
    baseOptions
  );
}
export type ResetUserPasswordHookResult = ReturnType<typeof useResetUserPassword>;
export type ResetUserPasswordMutationResult = ApolloReactCommon.MutationResult<ResetUserPassword>;
export type ResetUserPasswordMutationOptions = ApolloReactCommon.BaseMutationOptions<
  ResetUserPassword,
  ResetUserPasswordVariables
>;
