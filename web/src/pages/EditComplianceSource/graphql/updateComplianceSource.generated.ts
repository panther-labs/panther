/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import { ComplianceIntegrationDetails } from '../../../graphql/fragments/ComplianceIntegrationDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateComplianceSourceVariables = {
  input: Types.UpdateComplianceIntegrationInput;
};

export type UpdateComplianceSource = { updateComplianceIntegration: ComplianceIntegrationDetails };

export const UpdateComplianceSourceDocument = gql`
  mutation UpdateComplianceSource($input: UpdateComplianceIntegrationInput!) {
    updateComplianceIntegration(input: $input) {
      ...ComplianceIntegrationDetails
    }
  }
  ${ComplianceIntegrationDetails}
`;
export type UpdateComplianceSourceMutationFn = ApolloReactCommon.MutationFunction<
  UpdateComplianceSource,
  UpdateComplianceSourceVariables
>;

/**
 * __useUpdateComplianceSource__
 *
 * To run a mutation, you first call `useUpdateComplianceSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateComplianceSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateComplianceSource, { data, loading, error }] = useUpdateComplianceSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateComplianceSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    UpdateComplianceSource,
    UpdateComplianceSourceVariables
  >
) {
  return ApolloReactHooks.useMutation<UpdateComplianceSource, UpdateComplianceSourceVariables>(
    UpdateComplianceSourceDocument,
    baseOptions
  );
}
export type UpdateComplianceSourceHookResult = ReturnType<typeof useUpdateComplianceSource>;
export type UpdateComplianceSourceMutationResult = ApolloReactCommon.MutationResult<
  UpdateComplianceSource
>;
export type UpdateComplianceSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateComplianceSource,
  UpdateComplianceSourceVariables
>;
