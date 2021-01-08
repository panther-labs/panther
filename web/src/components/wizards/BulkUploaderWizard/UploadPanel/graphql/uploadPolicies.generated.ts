/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UploadPoliciesVariables = {
  input: Types.UploadPoliciesInput;
};

export type UploadPolicies = {
  uploadPolicies?: Types.Maybe<
    Pick<
      Types.UploadPoliciesResponse,
      | 'totalPolicies'
      | 'modifiedPolicies'
      | 'newPolicies'
      | 'totalRules'
      | 'modifiedRules'
      | 'newRules'
      | 'totalGlobals'
      | 'newGlobals'
      | 'modifiedGlobals'
    >
  >;
};

export const UploadPoliciesDocument = gql`
  mutation UploadPolicies($input: UploadPoliciesInput!) {
    uploadPolicies(input: $input) {
      totalPolicies
      modifiedPolicies
      newPolicies
      totalRules
      modifiedRules
      newRules
      totalGlobals
      newGlobals
      modifiedGlobals
    }
  }
`;
export type UploadPoliciesMutationFn = ApolloReactCommon.MutationFunction<
  UploadPolicies,
  UploadPoliciesVariables
>;

/**
 * __useUploadPolicies__
 *
 * To run a mutation, you first call `useUploadPolicies` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUploadPolicies` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [uploadPolicies, { data, loading, error }] = useUploadPolicies({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUploadPolicies(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UploadPolicies, UploadPoliciesVariables>
) {
  return ApolloReactHooks.useMutation<UploadPolicies, UploadPoliciesVariables>(
    UploadPoliciesDocument,
    baseOptions
  );
}
export type UploadPoliciesHookResult = ReturnType<typeof useUploadPolicies>;
export type UploadPoliciesMutationResult = ApolloReactCommon.MutationResult<UploadPolicies>;
export type UploadPoliciesMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UploadPolicies,
  UploadPoliciesVariables
>;
export function mockUploadPolicies({
  data,
  variables,
  errors,
}: {
  data: UploadPolicies;
  variables?: UploadPoliciesVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UploadPoliciesDocument, variables },
    result: { data, errors },
  };
}
