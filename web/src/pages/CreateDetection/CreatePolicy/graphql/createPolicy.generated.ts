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

import * as Types from '../../../../../__generated__/schema';

import { PolicyDetails } from '../../../../graphql/fragments/PolicyDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type CreatePolicyVariables = {
  input: Types.AddPolicyInput;
};

export type CreatePolicy = { addPolicy: PolicyDetails };

export const CreatePolicyDocument = gql`
  mutation CreatePolicy($input: AddPolicyInput!) {
    addPolicy(input: $input) {
      ...PolicyDetails
    }
  }
  ${PolicyDetails}
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
export function mockCreatePolicy({
  data,
  variables,
  errors,
}: {
  data: CreatePolicy;
  variables?: CreatePolicyVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: CreatePolicyDocument, variables },
    result: { data, errors },
  };
}
