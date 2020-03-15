/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type AddInfraSourceVariables = {
  input: Types.AddIntegrationInput;
};

export type AddInfraSource = {
  addIntegration: Types.Maybe<Pick<Types.Integration, 'integrationId'>>;
};

export const AddInfraSourceDocument = gql`
  mutation AddInfraSource($input: AddIntegrationInput!) {
    addIntegration(input: $input) {
      integrationId
    }
  }
`;
export type AddInfraSourceMutationFn = ApolloReactCommon.MutationFunction<
  AddInfraSource,
  AddInfraSourceVariables
>;

/**
 * __useAddInfraSource__
 *
 * To run a mutation, you first call `useAddInfraSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useAddInfraSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [addInfraSource, { data, loading, error }] = useAddInfraSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useAddInfraSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<AddInfraSource, AddInfraSourceVariables>
) {
  return ApolloReactHooks.useMutation<AddInfraSource, AddInfraSourceVariables>(
    AddInfraSourceDocument,
    baseOptions
  );
}
export type AddInfraSourceHookResult = ReturnType<typeof useAddInfraSource>;
export type AddInfraSourceMutationResult = ApolloReactCommon.MutationResult<AddInfraSource>;
export type AddInfraSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  AddInfraSource,
  AddInfraSourceVariables
>;
