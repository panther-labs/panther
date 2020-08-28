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

import { S3LogIntegrationDetails } from '../../../graphql/fragments/S3LogIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateS3LogSourceVariables = {
  input: Types.UpdateS3LogIntegrationInput;
};

export type UpdateS3LogSource = { updateS3LogIntegration: S3LogIntegrationDetails };

export const UpdateS3LogSourceDocument = gql`
  mutation UpdateS3LogSource($input: UpdateS3LogIntegrationInput!) {
    updateS3LogIntegration(input: $input) {
      ...S3LogIntegrationDetails
    }
  }
  ${S3LogIntegrationDetails}
`;
export type UpdateS3LogSourceMutationFn = ApolloReactCommon.MutationFunction<
  UpdateS3LogSource,
  UpdateS3LogSourceVariables
>;

/**
 * __useUpdateS3LogSource__
 *
 * To run a mutation, you first call `useUpdateS3LogSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateS3LogSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateS3LogSource, { data, loading, error }] = useUpdateS3LogSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateS3LogSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdateS3LogSource, UpdateS3LogSourceVariables>
) {
  return ApolloReactHooks.useMutation<UpdateS3LogSource, UpdateS3LogSourceVariables>(
    UpdateS3LogSourceDocument,
    baseOptions
  );
}
export type UpdateS3LogSourceHookResult = ReturnType<typeof useUpdateS3LogSource>;
export type UpdateS3LogSourceMutationResult = ApolloReactCommon.MutationResult<UpdateS3LogSource>;
export type UpdateS3LogSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateS3LogSource,
  UpdateS3LogSourceVariables
>;
export function mockUpdateS3LogSource({
  data,
  variables,
  errors,
}: {
  data: UpdateS3LogSource;
  variables?: UpdateS3LogSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UpdateS3LogSourceDocument, variables },
    result: { data, errors },
  };
}
