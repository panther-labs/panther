/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type TestPolicyVariables = {
  input?: Types.Maybe<Types.TestPolicyInput>;
};

export type TestPolicy = {
  testPolicy: Types.Maybe<
    Pick<Types.TestPolicyResponse, 'testSummary' | 'testsPassed' | 'testsFailed'> & {
      testsErrored: Types.Maybe<
        Array<Types.Maybe<Pick<Types.PolicyUnitTestError, 'errorMessage' | 'name'>>>
      >;
    }
  >;
};

export const TestPolicyDocument = gql`
  mutation TestPolicy($input: TestPolicyInput) {
    testPolicy(input: $input) {
      testSummary
      testsPassed
      testsFailed
      testsErrored {
        errorMessage
        name
      }
    }
  }
`;
export type TestPolicyMutationFn = ApolloReactCommon.MutationFunction<
  TestPolicy,
  TestPolicyVariables
>;

/**
 * __useTestPolicy__
 *
 * To run a mutation, you first call `useTestPolicy` within a React component and pass it any options that fit your needs.
 * When your component renders, `useTestPolicy` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [testPolicy, { data, loading, error }] = useTestPolicy({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useTestPolicy(
  baseOptions?: ApolloReactHooks.MutationHookOptions<TestPolicy, TestPolicyVariables>
) {
  return ApolloReactHooks.useMutation<TestPolicy, TestPolicyVariables>(
    TestPolicyDocument,
    baseOptions
  );
}
export type TestPolicyHookResult = ReturnType<typeof useTestPolicy>;
export type TestPolicyMutationResult = ApolloReactCommon.MutationResult<TestPolicy>;
export type TestPolicyMutationOptions = ApolloReactCommon.BaseMutationOptions<
  TestPolicy,
  TestPolicyVariables
>;
