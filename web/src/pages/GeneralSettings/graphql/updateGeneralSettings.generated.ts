/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type UpdateGeneralSettingsVariables = {
  input: Types.UpdateGeneralSettingsInput;
};

export type UpdateGeneralSettings = {
  updateGeneralSettings: Pick<
    Types.GeneralSettings,
    'displayName' | 'email' | 'errorReportingConsent'
  >;
};

export const UpdateGeneralSettingsDocument = gql`
  mutation UpdateGeneralSettings($input: UpdateGeneralSettingsInput!) {
    updateGeneralSettings(input: $input) {
      displayName
      email
      errorReportingConsent
    }
  }
`;
export type UpdateGeneralSettingsMutationFn = ApolloReactCommon.MutationFunction<
  UpdateGeneralSettings,
  UpdateGeneralSettingsVariables
>;

/**
 * __useUpdateGeneralSettings__
 *
 * To run a mutation, you first call `useUpdateGeneralSettings` within a React component and pass it any options that fit your needs.
 * When your component renders, `useUpdateGeneralSettings` returns a tuple that includes:
 * - A mutate function that you can call at any time to execute the mutation
 * - An object with fields that represent the current status of the mutation's execution
 *
 * @param baseOptions options that will be passed into the mutation, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options-2;
 *
 * @example
 * const [updateGeneralSettings, { data, loading, error }] = useUpdateGeneralSettings({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useUpdateGeneralSettings(
  baseOptions?: ApolloReactHooks.MutationHookOptions<
    UpdateGeneralSettings,
    UpdateGeneralSettingsVariables
  >
) {
  return ApolloReactHooks.useMutation<UpdateGeneralSettings, UpdateGeneralSettingsVariables>(
    UpdateGeneralSettingsDocument,
    baseOptions
  );
}
export type UpdateGeneralSettingsHookResult = ReturnType<typeof useUpdateGeneralSettings>;
export type UpdateGeneralSettingsMutationResult = ApolloReactCommon.MutationResult<
  UpdateGeneralSettings
>;
export type UpdateGeneralSettingsMutationOptions = ApolloReactCommon.BaseMutationOptions<
  UpdateGeneralSettings,
  UpdateGeneralSettingsVariables
>;
