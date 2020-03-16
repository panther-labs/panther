/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
