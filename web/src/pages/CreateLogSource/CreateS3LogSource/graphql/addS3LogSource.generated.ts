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

import * as Types from '../../../../../__generated__/schema';

import { S3LogIntegrationDetails } from '../../../../graphql/fragments/S3LogIntegrationDetails.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type AddS3LogSourceVariables = {
  input: Types.AddS3LogIntegrationInput;
};

export type AddS3LogSource = { addS3LogIntegration: S3LogIntegrationDetails };

export const AddS3LogSourceDocument = gql`
  mutation AddS3LogSource($input: AddS3LogIntegrationInput!) {
    addS3LogIntegration(input: $input) {
      ...S3LogIntegrationDetails
    }
  }
  ${S3LogIntegrationDetails}
`;
export type AddS3LogSourceMutationFn = ApolloReactCommon.MutationFunction<
  AddS3LogSource,
  AddS3LogSourceVariables
>;

/**
 * __useAddS3LogSource__
 *
 * To run a mutation, you first call `useAddS3LogSource` within a React component and pass it any options that fit your needs.
 * When your component renders, `useAddS3LogSource` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [addS3LogSource, { data, loading, error }] = useAddS3LogSource({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useAddS3LogSource(
  baseOptions?: ApolloReactHooks.MutationHookOptions<AddS3LogSource, AddS3LogSourceVariables>
) {
  return ApolloReactHooks.useMutation<AddS3LogSource, AddS3LogSourceVariables>(
    AddS3LogSourceDocument,
    baseOptions
  );
}
export type AddS3LogSourceHookResult = ReturnType<typeof useAddS3LogSource>;
export type AddS3LogSourceMutationResult = ApolloReactCommon.MutationResult<AddS3LogSource>;
export type AddS3LogSourceMutationOptions = ApolloReactCommon.BaseMutationOptions<
  AddS3LogSource,
  AddS3LogSourceVariables
>;
export function mockAddS3LogSource({
  data,
  variables,
  errors,
}: {
  data: AddS3LogSource;
  variables?: AddS3LogSourceVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: AddS3LogSourceDocument, variables },
    result: { data, errors },
  };
}
