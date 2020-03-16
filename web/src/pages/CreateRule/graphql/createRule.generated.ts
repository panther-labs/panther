/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type CreateRuleVariables = {
  input: Types.CreateOrModifyRuleInput;
};

export type CreateRule = {
  addRule: Types.Maybe<
    Pick<
      Types.RuleDetails,
      | 'description'
      | 'displayName'
      | 'enabled'
      | 'id'
      | 'reference'
      | 'logTypes'
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

export const CreateRuleDocument = gql`
  mutation CreateRule($input: CreateOrModifyRuleInput!) {
    addRule(input: $input) {
      description
      displayName
      enabled
      id
      reference
      logTypes
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
export type CreateRuleMutationFn = ApolloReactCommon.MutationFunction<
  CreateRule,
  CreateRuleVariables
>;

/**
 * __useCreateRule__
 *
 * To run a mutation, you first call `useCreateRule` within a React component and pass it any options that fit your needs.
 * When your component renders, `useCreateRule` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [createRule, { data, loading, error }] = useCreateRule({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useCreateRule(
  baseOptions?: ApolloReactHooks.MutationHookOptions<CreateRule, CreateRuleVariables>
) {
  return ApolloReactHooks.useMutation<CreateRule, CreateRuleVariables>(
    CreateRuleDocument,
    baseOptions
  );
}
export type CreateRuleHookResult = ReturnType<typeof useCreateRule>;
export type CreateRuleMutationResult = ApolloReactCommon.MutationResult<CreateRule>;
export type CreateRuleMutationOptions = ApolloReactCommon.BaseMutationOptions<
  CreateRule,
  CreateRuleVariables
>;
