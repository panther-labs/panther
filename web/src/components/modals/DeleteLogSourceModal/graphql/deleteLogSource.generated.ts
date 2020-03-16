/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type DeleteLogSourceVariables = {
  id: Types.Scalars['ID'];
};

export type DeleteLogSource = Pick<Types.Mutation, 'deleteLogIntegration'>;

export const DeleteLogSourceDocument = gql`
  mutation DeleteLogSource($id: ID!) {
    deleteLogIntegration(id: $id)
  }
`;
export type DeleteLogSourceMutationFn = ApolloReactCommon.MutationFunction<
  DeleteLogSource,
  DeleteLogSourceVariables
>;

/**
 * __useDeleteLogSource__
 *
 * To run a mutation, you first call `useDeleteLogSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useDeleteLogSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [deleteLogSource, { data, loading, error }] = useDeleteLogSource({
 *   variables: {
 *      id: // value for 'id'
 *   },
 * });
 */
export function useDeleteLogSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<DeleteLogSource, DeleteLogSourceVariables>
) {
  return ApolloReactHooks.useMutation<DeleteLogSource, DeleteLogSourceVariables>(
    DeleteLogSourceDocument,
    baseOptions
  );
}
export type DeleteLogSourceHookResult = ReturnType<typeof useDeleteLogSource>;
export type DeleteLogSourceMutationResult = ApolloReactCommon.MutationResult<DeleteLogSource>;
export type DeleteLogSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  DeleteLogSource,
  DeleteLogSourceVariables
>;
