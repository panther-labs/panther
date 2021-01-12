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

import { DataModelFull } from '../../../graphql/fragments/DataModelFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateDataModelVariables = {
  input: Types.AddOrUpdateDataModelInput;
};

export type UpdateDataModel = { updateDataModel: DataModelFull };

export const UpdateDataModelDocument = gql`
  mutation UpdateDataModel($input: AddOrUpdateDataModelInput!) {
    updateDataModel(input: $input) {
      ...DataModelFull
    }
  }
  ${DataModelFull}
`;
export type UpdateDataModelMutationFn = ApolloReactCommon.MutationFunction<
  UpdateDataModel,
  UpdateDataModelVariables
>;

/**
 * __useUpdateDataModel__
 *
 * To run a mutation, you first call `useUpdateDataModel` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateDataModel` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateDataModel, { data, loading, error }] = useUpdateDataModel({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateDataModel(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdateDataModel, UpdateDataModelVariables>
) {
  return ApolloReactHooks.useMutation<UpdateDataModel, UpdateDataModelVariables>(
    UpdateDataModelDocument,
    baseOptions
  );
}
export type UpdateDataModelHookResult = ReturnType<typeof useUpdateDataModel>;
export type UpdateDataModelMutationResult = ApolloReactCommon.MutationResult<UpdateDataModel>;
export type UpdateDataModelMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateDataModel,
  UpdateDataModelVariables
>;
export function mockUpdateDataModel({
  data,
  variables,
  errors,
}: {
  data: UpdateDataModel;
  variables?: UpdateDataModelVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UpdateDataModelDocument, variables },
    result: { data, errors },
  };
}
