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

export type TestRuleVariables = {
  input: Types.TestRuleInput;
};

export type TestRule = {
  testRule: {
    results: Array<
      Pick<Types.TestRuleRecord, 'id' | 'name' | 'passed'> & {
        error?: Types.Maybe<Pick<Types.Error, 'message'>>;
        functions: {
          ruleFunction: TestFunctionResult;
          titleFunction?: Types.Maybe<TestFunctionResult>;
          dedupFunction?: Types.Maybe<TestFunctionResult>;
          alertContextFunction?: Types.Maybe<TestFunctionResult>;
          descriptionFunction?: Types.Maybe<TestFunctionResult>;
          destinationsFunction?: Types.Maybe<TestFunctionResult>;
          referenceFunction?: Types.Maybe<TestFunctionResult>;
          runbookFunction?: Types.Maybe<TestFunctionResult>;
          severityFunction?: Types.Maybe<TestFunctionResult>;
        };
      }
    >;
  };
};

export const TestRuleDocument = gql`
  mutation TestRule($input: TestRuleInput!) {
    testRule(input: $input) {
      results {
        id
        name
        passed
        error {
          message
        }
        functions {
          ruleFunction {
            ...TestFunctionResult
          }
          titleFunction {
            ...TestFunctionResult
          }
          dedupFunction {
            ...TestFunctionResult
          }
          alertContextFunction {
            ...TestFunctionResult
          }
          descriptionFunction {
            ...TestFunctionResult
          }
          destinationsFunction {
            ...TestFunctionResult
          }
          referenceFunction {
            ...TestFunctionResult
          }
          runbookFunction {
            ...TestFunctionResult
          }
          severityFunction {
            ...TestFunctionResult
          }
        }
      }
    }
  }
  ${TestFunctionResult}
`;
export type TestRuleMutationFn = ApolloReactCommon.MutationFunction<TestRule, TestRuleVariables>;

/**
 * __useTestRule__
 *
 * To run a mutation, you first call `useTestRule` within a React component and pass it any options that fit your needs.
 * When your component renders, `useTestRule` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [testRule, { data, loading, error }] = useTestRule({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useTestRule(
  baseOptions?: ApolloReactHooks.MutationHookOptions<TestRule, TestRuleVariables>
) {
  return ApolloReactHooks.useMutation<TestRule, TestRuleVariables>(TestRuleDocument, baseOptions);
}
export type TestRuleHookResult = ReturnType<typeof useTestRule>;
export type TestRuleMutationResult = ApolloReactCommon.MutationResult<TestRule>;
export type TestRuleMutationOptions = ApolloReactCommon.BaseMutationOptions<
  TestRule,
  TestRuleVariables
>;
export function mockTestRule({
  data,
  variables,
  errors,
}: {
  data: TestRule;
  variables?: TestRuleVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: TestRuleDocument, variables },
    result: { data, errors },
  };
}
