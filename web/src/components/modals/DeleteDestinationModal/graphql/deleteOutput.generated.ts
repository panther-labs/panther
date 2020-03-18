/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteOutputVariables = {
  id: Types.Scalars['ID'];
};

export type DeleteOutput = Pick<Types.Mutation, 'deleteDestination'>;

export const DeleteOutputDocument = gql`
  mutation DeleteOutput($id: ID!) {
    deleteDestination(id: $id)
  }
`;
export type DeleteOutputMutationFn = ApolloReactCommon.MutationFunction<
  DeleteOutput,
  DeleteOutputVariables
>;

/**
 * __useDeleteOutput__
 *
 * To run a mutation, you first call `useDeleteOutput` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteOutput` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteOutput, { data, loading, error }] = useDeleteOutput({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useDeleteOutput(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteOutput, DeleteOutputVariables>
) {
  return ApolloReactHooks.useMutation<DeleteOutput, DeleteOutputVariables>(
    DeleteOutputDocument,
    baseOptions
  );
}
export type DeleteOutputHookResult = ReturnType<typeof useDeleteOutput>;
export type DeleteOutputMutationResult = ApolloReactCommon.MutationResult<DeleteOutput>;
export type DeleteOutputMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteOutput,
  DeleteOutputVariables
>;
