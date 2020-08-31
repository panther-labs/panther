/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import * as Types from '../../../__generated__/schema';

import { GraphQLError } from 'graphql';
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
export function mockRemediateResource({
  data,
  variables,
  errors,
}: {
  data: RemediateResource;
  variables?: RemediateResourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: RemediateResourceDocument, variables },
    result: { data, errors },
  };
}
