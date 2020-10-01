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

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateGeneralSettingsConsentsVariables = {
  input: Types.UpdateGeneralSettingsInput;
};

export type UpdateGeneralSettingsConsents = {
  updateGeneralSettings: Pick<
    Types.GeneralSettings,
    'email' | 'errorReportingConsent' | 'analyticsConsent'
  >;
};

export const UpdateGeneralSettingsConsentsDocument = gql`
  mutation UpdateGeneralSettingsConsents($input: UpdateGeneralSettingsInput!) {
    updateGeneralSettings(input: $input) {
      email
      errorReportingConsent
      analyticsConsent
    }
  }
`;
export type UpdateGeneralSettingsConsentsMutationFn = ApolloReactCommon.MutationFunction<
  UpdateGeneralSettingsConsents,
  UpdateGeneralSettingsConsentsVariables
>;

/**
 * __useUpdateGeneralSettingsConsents__
 *
 * To run a mutation, you first call `useUpdateGeneralSettingsConsents` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateGeneralSettingsConsents` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateGeneralSettingsConsents, { data, loading, error }] = useUpdateGeneralSettingsConsents({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateGeneralSettingsConsents(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    UpdateGeneralSettingsConsents,
    UpdateGeneralSettingsConsentsVariables
  >
) {
  return ApolloReactHooks.useMutation<
    UpdateGeneralSettingsConsents,
    UpdateGeneralSettingsConsentsVariables
  >(UpdateGeneralSettingsConsentsDocument, baseOptions);
}
export type UpdateGeneralSettingsConsentsHookResult = ReturnType<
  typeof useUpdateGeneralSettingsConsents
>;
export type UpdateGeneralSettingsConsentsMutationResult = ApolloReactCommon.MutationResult<
  UpdateGeneralSettingsConsents
>;
export type UpdateGeneralSettingsConsentsMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateGeneralSettingsConsents,
  UpdateGeneralSettingsConsentsVariables
>;
export function mockUpdateGeneralSettingsConsents({
  data,
  variables,
  errors,
}: {
  data: UpdateGeneralSettingsConsents;
  variables?: UpdateGeneralSettingsConsentsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: UpdateGeneralSettingsConsentsDocument, variables },
    result: { data, errors },
  };
}
