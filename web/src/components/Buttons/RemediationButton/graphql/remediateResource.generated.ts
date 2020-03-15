/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type RemediateResourceVariables = {
  input: Types.RemediateResourceInput;
};

export type RemediateResource = Pick<Types.Mutation, 'remediateResource'>;

export const RemediateResourceDocument = gql`
  mutation RemediateResource($input: RemediateResourceInput!) {
    remediateResource(input: $input)
  }
`;
export type RemediateResourceMutationFn = ApolloReactCommon.MutationFunction<
  RemediateResource,
  RemediateResourceVariables
>;

/**
 * __useRemediateResource__
 *
 * To run a mutation, you first call `useRemediateResource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useRemediateResource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [remediateResource, { data, loading, error }] = useRemediateResource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useRemediateResource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<RemediateResource, RemediateResourceVariables>
) {
  return ApolloReactHooks.useMutation<RemediateResource, RemediateResourceVariables>(
    RemediateResourceDocument,
    baseOptions
  );
}
export type RemediateResourceHookResult = ReturnType<typeof useRemediateResource>;
export type RemediateResourceMutationResult = ApolloReactCommon.MutationResult<RemediateResource>;
export type RemediateResourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  RemediateResource,
  RemediateResourceVariables
>;
