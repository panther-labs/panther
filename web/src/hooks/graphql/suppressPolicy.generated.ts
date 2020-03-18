/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type SuppressPolicyVariables = {
  input: Types.SuppressPoliciesInput;
};

export type SuppressPolicy = Pick<Types.Mutation, 'suppressPolicies'>;

export const SuppressPolicyDocument = gql`
  mutation SuppressPolicy($input: SuppressPoliciesInput!) {
    suppressPolicies(input: $input)
  }
`;
export type SuppressPolicyMutationFn = ApolloReactCommon.MutationFunction<
  SuppressPolicy,
  SuppressPolicyVariables
>;

/**
 * __useSuppressPolicy__
 *
 * To run a mutation, you first call `useSuppressPolicy` within a React component and pass it any options that fit your needs.
 * When your component renders, `useSuppressPolicy` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [suppressPolicy, { data, loading, error }] = useSuppressPolicy({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useSuppressPolicy(
  baseOptions?: ApolloReactHooks.MutationHookOptions<SuppressPolicy, SuppressPolicyVariables>
) {
  return ApolloReactHooks.useMutation<SuppressPolicy, SuppressPolicyVariables>(
    SuppressPolicyDocument,
    baseOptions
  );
}
export type SuppressPolicyHookResult = ReturnType<typeof useSuppressPolicy>;
export type SuppressPolicyMutationResult = ApolloReactCommon.MutationResult<SuppressPolicy>;
export type SuppressPolicyMutationOptions = ApolloReactCommon.BaseMutationOptions<
  SuppressPolicy,
  SuppressPolicyVariables
>;
