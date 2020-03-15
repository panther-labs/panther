/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type CreatePolicyVariables = {
  input: Types.CreateOrModifyPolicyInput;
};

export type CreatePolicy = {
  addPolicy: Types.Maybe<
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

export const CreatePolicyDocument = gql`
  mutation CreatePolicy($input: CreateOrModifyPolicyInput!) {
    addPolicy(input: $input) {
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
export type CreatePolicyMutationFn = ApolloReactCommon.MutationFunction<
  CreatePolicy,
  CreatePolicyVariables
>;

/**
 * __useCreatePolicy__
 *
 * To run a mutation, you first call `useCreatePolicy` within a React component and pass it any options that fit your needs.
 * When your component renders, `useCreatePolicy` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [createPolicy, { data, loading, error }] = useCreatePolicy({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useCreatePolicy(
  baseOptions?: ApolloReactHooks.MutationHookOptions<CreatePolicy, CreatePolicyVariables>
) {
  return ApolloReactHooks.useMutation<CreatePolicy, CreatePolicyVariables>(
    CreatePolicyDocument,
    baseOptions
  );
}
export type CreatePolicyHookResult = ReturnType<typeof useCreatePolicy>;
export type CreatePolicyMutationResult = ApolloReactCommon.MutationResult<CreatePolicy>;
export type CreatePolicyMutationOptions = ApolloReactCommon.BaseMutationOptions<
  CreatePolicy,
  CreatePolicyVariables
>;
