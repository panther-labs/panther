/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeletePolicyVariables = {
  input: Types.DeletePolicyInput;
};

export type DeletePolicy = Pick<Types.Mutation, 'deletePolicy'>;

export const DeletePolicyDocument = gql`
  mutation DeletePolicy($input: DeletePolicyInput!) {
    deletePolicy(input: $input)
  }
`;
export type DeletePolicyMutationFn = ApolloReactCommon.MutationFunction<
  DeletePolicy,
  DeletePolicyVariables
>;

/**
 * __useDeletePolicy__
 *
 * To run a mutation, you first call `useDeletePolicy` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeletePolicy` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deletePolicy, { data, loading, error }] = useDeletePolicy({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useDeletePolicy(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeletePolicy, DeletePolicyVariables>
) {
  return ApolloReactHooks.useMutation<DeletePolicy, DeletePolicyVariables>(
    DeletePolicyDocument,
    baseOptions
  );
}
export type DeletePolicyHookResult = ReturnType<typeof useDeletePolicy>;
export type DeletePolicyMutationResult = ApolloReactCommon.MutationResult<DeletePolicy>;
export type DeletePolicyMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeletePolicy,
  DeletePolicyVariables
>;
