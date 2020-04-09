/**
 * A Cloud-Native SIEM for the Modern Security Team
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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../../__generated__/schema';

import { LogIntegrationDetails } from '../../../graphql/fragments/LogIntegrationDetails.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateLogSourceVariables = {
  input: Types.UpdateLogIntegrationInput;
};

export type UpdateLogSource = { updateLogIntegration: LogIntegrationDetails };

export const UpdateLogSourceDocument = gql`
  mutation UpdateLogSource($input: UpdateLogIntegrationInput!) {
    updateLogIntegration(input: $input) {
      ...LogIntegrationDetails
    }
  }
  ${LogIntegrationDetails}
`;
export type UpdateLogSourceMutationFn = ApolloReactCommon.MutationFunction<
  UpdateLogSource,
  UpdateLogSourceVariables
>;

/**
 * __useUpdateLogSource__
 *
 * To run a mutation, you first call `useUpdateLogSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateLogSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateLogSource, { data, loading, error }] = useUpdateLogSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateLogSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdateLogSource, UpdateLogSourceVariables>
) {
  return ApolloReactHooks.useMutation<UpdateLogSource, UpdateLogSourceVariables>(
    UpdateLogSourceDocument,
    baseOptions
  );
}
export type UpdateLogSourceHookResult = ReturnType<typeof useUpdateLogSource>;
export type UpdateLogSourceMutationResult = ApolloReactCommon.MutationResult<UpdateLogSource>;
export type UpdateLogSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateLogSource,
  UpdateLogSourceVariables
>;
