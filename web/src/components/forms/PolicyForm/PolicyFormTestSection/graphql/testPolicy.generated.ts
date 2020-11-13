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

import * as Types from '../../../../../../__generated__/schema';

import { TestFunctionResult } from '../../../../../graphql/fragments/TestFunctionResult.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type TestPolicyVariables = {
  input: Types.TestPolicyInput;
};

export type TestPolicy = {
  testPolicy: {
    results: Array<
      Pick<Types.TestPolicyRecord, 'id' | 'name' | 'passed'> & {
        error?: Types.Maybe<Pick<Types.Error, 'message'>>;
        functions: { policyFunction: TestFunctionResult };
      }
    >;
  };
};

export const TestPolicyDocument = gql`
  mutation TestPolicy($input: TestPolicyInput!) {
    testPolicy(input: $input) {
      results {
        id
        name
        passed
        error {
          message
        }
        functions {
          policyFunction {
            ...TestFunctionResult
          }
        }
      }
    }
  }
  ${TestFunctionResult}
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
export function mockTestPolicy({
  data,
  variables,
  errors,
}: {
  data: TestPolicy;
  variables?: TestPolicyVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: TestPolicyDocument, variables },
    result: { data, errors },
  };
}
