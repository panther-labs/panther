/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdatePolicyVariables = {
  input: Types.CreateOrModifyPolicyInput;
};

export type UpdatePolicy = {
  updatePolicy: Types.Maybe<
    Pick<
      Types.PolicyDetails,
      | 'autoRemediationId'
      | 'autoRemediationParameters'
      | 'description'
      | 'displayName'
      | 'enabled'
      | 'suppressions'
      | 'id'
      | 'reference'
      | 'resourceTypes'
      | 'runbook'
      | 'severity'
      | 'tags'
      | 'body'
    > & {
      tests: Types.Maybe<
        Array<
          Types.Maybe<
            Pick<Types.PolicyUnitTest, 'expectedResult' | 'name' | 'resource' | 'resourceType'>
          >
        >
      >;
    }
  >;
};

export const UpdatePolicyDocument = gql`
  mutation UpdatePolicy($input: CreateOrModifyPolicyInput!) {
    updatePolicy(input: $input) {
      autoRemediationId
      autoRemediationParameters
      description
      displayName
      enabled
      suppressions
      id
      reference
      resourceTypes
      runbook
      severity
      tags
      body
      tests {
        expectedResult
        name
        resource
        resourceType
      }
    }
  }
`;
export type UpdatePolicyMutationFn = ApolloReactCommon.MutationFunction<
  UpdatePolicy,
  UpdatePolicyVariables
>;

/**
 * __useUpdatePolicy__
 *
 * To run a mutation, you first call `useUpdatePolicy` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdatePolicy` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updatePolicy, { data, loading, error }] = useUpdatePolicy({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdatePolicy(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdatePolicy, UpdatePolicyVariables>
) {
  return ApolloReactHooks.useMutation<UpdatePolicy, UpdatePolicyVariables>(
    UpdatePolicyDocument,
    baseOptions
  );
}
export type UpdatePolicyHookResult = ReturnType<typeof useUpdatePolicy>;
export type UpdatePolicyMutationResult = ApolloReactCommon.MutationResult<UpdatePolicy>;
export type UpdatePolicyMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdatePolicy,
  UpdatePolicyVariables
>;
