/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type AddComplianceSourceVariables = {
  input: Types.AddComplianceIntegrationInput;
};

export type AddComplianceSource = {
  addComplianceIntegration: Pick<Types.ComplianceIntegration, 'integrationId'>;
};

export const AddComplianceSourceDocument = gql`
  mutation AddComplianceSource($input: AddComplianceIntegrationInput!) {
    addComplianceIntegration(input: $input) {
      integrationId
    }
  }
`;
export type AddComplianceSourceMutationFn = ApolloReactCommon.MutationFunction<
  AddComplianceSource,
  AddComplianceSourceVariables
>;

/**
 * __useAddComplianceSource__
 *
 * To run a mutation, you first call `useAddComplianceSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useAddComplianceSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [addComplianceSource, { data, loading, error }] = useAddComplianceSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useAddComplianceSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    AddComplianceSource,
    AddComplianceSourceVariables
  >
) {
  return ApolloReactHooks.useMutation<AddComplianceSource, AddComplianceSourceVariables>(
    AddComplianceSourceDocument,
    baseOptions
  );
}
export type AddComplianceSourceHookResult = ReturnType<typeof useAddComplianceSource>;
export type AddComplianceSourceMutationResult = ApolloReactCommon.MutationResult<
  AddComplianceSource
>;
export type AddComplianceSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  AddComplianceSource,
  AddComplianceSourceVariables
>;
