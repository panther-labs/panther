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

export type UpdateCustomLogVariables = {
  input: Types.AddOrUpdateCustomLogInput;
};

export type UpdateCustomLog = {
  updateCustomLog: {
    error?: Types.Maybe<Pick<Types.Error, 'message'>>;
    record?: Types.Maybe<CustomLogFull>;
  };
};

export const UpdateCustomLogDocument = gql`
  mutation UpdateCustomLog($input: AddOrUpdateCustomLogInput!) {
    updateCustomLog(input: $input) {
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
export type UpdateCustomLogMutationFn = ApolloReactCommon.MutationFunction<
  UpdateCustomLog,
  UpdateCustomLogVariables
>;

/**
 * __useUpdateCustomLog__
 *
 * To run a mutation, you first call `useUpdateCustomLog` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateCustomLog` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateCustomLog, { data, loading, error }] = useUpdateCustomLog({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateCustomLog(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdateCustomLog, UpdateCustomLogVariables>
) {
  return ApolloReactHooks.useMutation<UpdateCustomLog, UpdateCustomLogVariables>(
    UpdateCustomLogDocument,
    baseOptions
  );
}
export type UpdateCustomLogHookResult = ReturnType<typeof useUpdateCustomLog>;
export type UpdateCustomLogMutationResult = ApolloReactCommon.MutationResult<UpdateCustomLog>;
export type UpdateCustomLogMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateCustomLog,
  UpdateCustomLogVariables
>;
export function mockUpdateCustomLog({
  data,
  variables,
  errors,
}: {
  data: UpdateCustomLog;
  variables?: UpdateCustomLogVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UpdateCustomLogDocument, variables },
    result: { data, errors },
  };
}
