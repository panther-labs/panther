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

import { AnalysisPackSummary } from '../fragments/AnalysisPackSummary.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateAnalysisPackVariables = {
  input: Types.UpdateAnalysisPackInput;
};

export type UpdateAnalysisPack = { updateAnalysisPack: AnalysisPackSummary };

export const UpdateAnalysisPackDocument = gql`
  mutation UpdateAnalysisPack($input: UpdateAnalysisPackInput!) {
    updateAnalysisPack(input: $input) {
      ...AnalysisPackSummary
    }
  }
  ${AnalysisPackSummary}
`;
export type UpdateAnalysisPackMutationFn = ApolloReactCommon.MutationFunction<
  UpdateAnalysisPack,
  UpdateAnalysisPackVariables
>;

/**
 * __useUpdateAnalysisPack__
 *
 * To run a mutation, you first call `useUpdateAnalysisPack` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateAnalysisPack` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateAnalysisPack, { data, loading, error }] = useUpdateAnalysisPack({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateAnalysisPack(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    UpdateAnalysisPack,
    UpdateAnalysisPackVariables
  >
) {
  return ApolloReactHooks.useMutation<UpdateAnalysisPack, UpdateAnalysisPackVariables>(
    UpdateAnalysisPackDocument,
    baseOptions
  );
}
export type UpdateAnalysisPackHookResult = ReturnType<typeof useUpdateAnalysisPack>;
export type UpdateAnalysisPackMutationResult = ApolloReactCommon.MutationResult<UpdateAnalysisPack>;
export type UpdateAnalysisPackMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateAnalysisPack,
  UpdateAnalysisPackVariables
>;
export function mockUpdateAnalysisPack({
  data,
  variables,
  errors,
}: {
  data: UpdateAnalysisPack;
  variables?: UpdateAnalysisPackVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UpdateAnalysisPackDocument, variables },
    result: { data, errors },
  };
}
