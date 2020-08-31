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

import * as Types from '../../../../__generated__/schema';

import { SqsLogSourceIntegrationDetails } from '../../../graphql/fragments/SqsLogSourceIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateSqsLogSourceVariables = {
  input: Types.UpdateSqsLogIntegrationInput;
};

export type UpdateSqsLogSource = { updateSqsLogIntegration: SqsLogSourceIntegrationDetails };

export const UpdateSqsLogSourceDocument = gql`
  mutation UpdateSqsLogSource($input: UpdateSqsLogIntegrationInput!) {
    updateSqsLogIntegration(input: $input) {
      ...SqsLogSourceIntegrationDetails
    }
  }
  ${SqsLogSourceIntegrationDetails}
`;
export type UpdateSqsLogSourceMutationFn = ApolloReactCommon.MutationFunction<
  UpdateSqsLogSource,
  UpdateSqsLogSourceVariables
>;

/**
 * __useUpdateSqsLogSource__
 *
 * To run a mutation, you first call `useUpdateSqsLogSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateSqsLogSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateSqsLogSource, { data, loading, error }] = useUpdateSqsLogSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateSqsLogSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    UpdateSqsLogSource,
    UpdateSqsLogSourceVariables
  >
) {
  return ApolloReactHooks.useMutation<UpdateSqsLogSource, UpdateSqsLogSourceVariables>(
    UpdateSqsLogSourceDocument,
    baseOptions
  );
}
export type UpdateSqsLogSourceHookResult = ReturnType<typeof useUpdateSqsLogSource>;
export type UpdateSqsLogSourceMutationResult = ApolloReactCommon.MutationResult<UpdateSqsLogSource>;
export type UpdateSqsLogSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateSqsLogSource,
  UpdateSqsLogSourceVariables
>;
export function mockUpdateSqsLogSource({
  data,
  variables,
  errors,
}: {
  data: UpdateSqsLogSource;
  variables?: UpdateSqsLogSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UpdateSqsLogSourceDocument, variables },
    result: { data, errors },
  };
}
