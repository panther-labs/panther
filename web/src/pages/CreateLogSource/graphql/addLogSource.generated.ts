/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type AddLogSourceVariables = {
  input: Types.AddIntegrationInput;
};

export type AddLogSource = {
  addIntegration: Types.Maybe<Pick<Types.Integration, 'integrationId'>>;
};

export const AddLogSourceDocument = gql`
  mutation AddLogSource($input: AddIntegrationInput!) {
    addIntegration(input: $input) {
      integrationId
    }
  }
`;
export type AddLogSourceMutationFn = ApolloReactCommon.MutationFunction<
  AddLogSource,
  AddLogSourceVariables
>;

/**
 * __useAddLogSource__
 *
 * To run a mutation, you first call `useAddLogSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useAddLogSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [addLogSource, { data, loading, error }] = useAddLogSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useAddLogSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<AddLogSource, AddLogSourceVariables>
) {
  return ApolloReactHooks.useMutation<AddLogSource, AddLogSourceVariables>(
    AddLogSourceDocument,
    baseOptions
  );
}
export type AddLogSourceHookResult = ReturnType<typeof useAddLogSource>;
export type AddLogSourceMutationResult = ApolloReactCommon.MutationResult<AddLogSource>;
export type AddLogSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  AddLogSource,
  AddLogSourceVariables
>;
