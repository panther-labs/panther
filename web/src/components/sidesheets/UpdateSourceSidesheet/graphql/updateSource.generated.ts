/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateSourceVariables = {
  input: Types.UpdateIntegrationInput;
};

export type UpdateSource = Pick<Types.Mutation, 'updateIntegration'>;

export const UpdateSourceDocument = gql`
  mutation UpdateSource($input: UpdateIntegrationInput!) {
    updateIntegration(input: $input)
  }
`;
export type UpdateSourceMutationFn = ApolloReactCommon.MutationFunction<
  UpdateSource,
  UpdateSourceVariables
>;

/**
 * __useUpdateSource__
 *
 * To run a mutation, you first call `useUpdateSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateSource, { data, loading, error }] = useUpdateSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdateSource, UpdateSourceVariables>
) {
  return ApolloReactHooks.useMutation<UpdateSource, UpdateSourceVariables>(
    UpdateSourceDocument,
    baseOptions
  );
}
export type UpdateSourceHookResult = ReturnType<typeof useUpdateSource>;
export type UpdateSourceMutationResult = ApolloReactCommon.MutationResult<UpdateSource>;
export type UpdateSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateSource,
  UpdateSourceVariables
>;
