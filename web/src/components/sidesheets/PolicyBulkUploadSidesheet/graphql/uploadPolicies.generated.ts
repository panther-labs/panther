/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UploadPoliciesVariables = {
  input: Types.UploadPoliciesInput;
};

export type UploadPolicies = {
  uploadPolicies: Types.Maybe<
    Pick<
      Types.UploadPoliciesResponse,
      | 'totalPolicies'
      | 'modifiedPolicies'
      | 'newPolicies'
      | 'totalRules'
      | 'modifiedRules'
      | 'newRules'
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
