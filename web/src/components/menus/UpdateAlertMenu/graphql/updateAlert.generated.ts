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

/* eslint-disable import/order, import/no-duplicates, @typescript-eslint/no-unused-vars */

import * as Types from '../../../../../__generated__/schema';

import { AlertSummaryFull } from '../../../../graphql/fragments/AlertSummaryFull.generated';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateAlertVariables = {
  input: Types.UpdateAlertInput;
};

export type UpdateAlert = { updateAlert?: Types.Maybe<AlertSummaryFull> };

export const UpdateAlertDocument = gql`
  mutation UpdateAlert($input: UpdateAlertInput!) {
    updateAlert(input: $input) {
      ...AlertSummaryFull
    }
  }
  ${AlertSummaryFull}
`;
export type UpdateAlertMutationFn = ApolloReactCommon.MutationFunction<
  UpdateAlert,
  UpdateAlertVariables
>;

/**
 * __useUpdateAlert__
 *
 * To run a mutation, you first call `useUpdateAlert` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateAlert` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateAlert, { data, loading, error }] = useUpdateAlert({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateAlert(
  baseOptions?: ApolloReactHooks.MutationHookOptions<UpdateAlert, UpdateAlertVariables>
) {
  return ApolloReactHooks.useMutation<UpdateAlert, UpdateAlertVariables>(
    UpdateAlertDocument,
    baseOptions
  );
}
export type UpdateAlertHookResult = ReturnType<typeof useUpdateAlert>;
export type UpdateAlertMutationResult = ApolloReactCommon.MutationResult<UpdateAlert>;
export type UpdateAlertMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateAlert,
  UpdateAlertVariables
>;
