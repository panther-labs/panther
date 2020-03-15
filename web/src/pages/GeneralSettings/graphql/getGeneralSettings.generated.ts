/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetGeneralSettingsVariables = {};

export type GetGeneralSettings = {
  generalSettings: Pick<Types.GeneralSettings, 'displayName' | 'email' | 'errorReportingConsent'>;
};

export const GetGeneralSettingsDocument = gql`
  query GetGeneralSettings {
    generalSettings {
      displayName
      email
      errorReportingConsent
    }
  }
`;

/**
 * __useGetGeneralSettings__
 *
 * To run a query within a React component, call `useGetGeneralSettings` and pass it any options that fit your needs.
 * When your component renders, `useGetGeneralSettings` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetGeneralSettings({
 *   variables: {
 *   },
 * });
 */
export function useGetGeneralSettings(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetGeneralSettings, GetGeneralSettingsVariables>
) {
  return ApolloReactHooks.useQuery<GetGeneralSettings, GetGeneralSettingsVariables>(
    GetGeneralSettingsDocument,
    baseOptions
  );
}
export function useGetGeneralSettingsLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetGeneralSettings,
    GetGeneralSettingsVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetGeneralSettings, GetGeneralSettingsVariables>(
    GetGeneralSettingsDocument,
    baseOptions
  );
}
export type GetGeneralSettingsHookResult = ReturnType<typeof useGetGeneralSettings>;
export type GetGeneralSettingsLazyQueryHookResult = ReturnType<
  typeof useGetGeneralSettingsLazyQuery
>;
export type GetGeneralSettingsQueryResult = ApolloReactCommon.QueryResult<
  GetGeneralSettings,
  GetGeneralSettingsVariables
>;
