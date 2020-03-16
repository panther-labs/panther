/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteSourceVariables = {
  id: Types.Scalars['ID'];
};

export type DeleteSource = Pick<Types.Mutation, 'deleteIntegration'>;

export const DeleteSourceDocument = gql`
  mutation DeleteSource($id: ID!) {
    deleteIntegration(id: $id)
  }
`;
export type DeleteSourceMutationFn = ApolloReactCommon.MutationFunction<
  DeleteSource,
  DeleteSourceVariables
>;

/**
 * __useDeleteSource__
 *
 * To run a mutation, you first call `useDeleteSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteSource, { data, loading, error }] = useDeleteSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useDeleteSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteSource, DeleteSourceVariables>
) {
  return ApolloReactHooks.useMutation<DeleteSource, DeleteSourceVariables>(
    DeleteSourceDocument,
    baseOptions
  );
}
export type DeleteSourceHookResult = ReturnType<typeof useDeleteSource>;
export type DeleteSourceMutationResult = ApolloReactCommon.MutationResult<DeleteSource>;
export type DeleteSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteSource,
  DeleteSourceVariables
>;
