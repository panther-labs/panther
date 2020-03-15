/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateGeneralSettingsConsentsVariables = {
  input: Types.UpdateGeneralSettingsInput;
};

export type UpdateGeneralSettingsConsents = {
  updateGeneralSettings: Pick<Types.GeneralSettings, 'email' | 'errorReportingConsent'>;
};

export const UpdateGeneralSettingsConsentsDocument = gql`
  mutation UpdateGeneralSettingsConsents($input: UpdateGeneralSettingsInput!) {
    updateGeneralSettings(input: $input) {
      email
      errorReportingConsent
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
