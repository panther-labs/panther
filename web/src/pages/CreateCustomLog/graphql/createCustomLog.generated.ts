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

import { CustomLogFull } from '../../../graphql/fragments/CustomLogFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type CreateCustomLogVariables = {
  input: Types.AddOrUpdateCustomLogInput;
};

export type CreateCustomLog = {
  addCustomLog: {
    error?: Types.Maybe<Pick<Types.Error, 'message'>>;
    record?: Types.Maybe<CustomLogFull>;
  };
};

export const CreateCustomLogDocument = gql`
  mutation CreateCustomLog($input: AddOrUpdateCustomLogInput!) {
    addCustomLog(input: $input) {
      error {
        message
      }
      record {
        ...CustomLogFull
      }
    }
  }
  ${CustomLogFull}
`;
export type CreateCustomLogMutationFn = ApolloReactCommon.MutationFunction<
  CreateCustomLog,
  CreateCustomLogVariables
>;

/**
 * __useCreateCustomLog__
 *
 * To run a mutation, you first call `useCreateCustomLog` within a React component and pass it any options that fit your needs.
 * When your component renders, `useCreateCustomLog` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [createCustomLog, { data, loading, error }] = useCreateCustomLog({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useCreateCustomLog(
  baseOptions?: ApolloReactHooks.MutationHookOptions<CreateCustomLog, CreateCustomLogVariables>
) {
  return ApolloReactHooks.useMutation<CreateCustomLog, CreateCustomLogVariables>(
    CreateCustomLogDocument,
    baseOptions
  );
}
export type CreateCustomLogHookResult = ReturnType<typeof useCreateCustomLog>;
export type CreateCustomLogMutationResult = ApolloReactCommon.MutationResult<CreateCustomLog>;
export type CreateCustomLogMutationOptions = ApolloReactCommon.BaseMutationOptions<
  CreateCustomLog,
  CreateCustomLogVariables
>;
export function mockCreateCustomLog({
  data,
  variables,
  errors,
}: {
  data: CreateCustomLog;
  variables?: CreateCustomLogVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: CreateCustomLogDocument, variables },
    result: { data, errors },
  };
}
