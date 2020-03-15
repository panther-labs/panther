/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetErrorReportingConsentVariables = {};

export type GetErrorReportingConsent = {
  generalSettings: Pick<Types.GeneralSettings, 'displayName' | 'email' | 'errorReportingConsent'>;
};

export const GetErrorReportingConsentDocument = gql`
  query GetErrorReportingConsent {
    generalSettings {
      displayName
      email
      errorReportingConsent
    }
  }
`;

/**
 * __useGetErrorReportingConsent__
 *
 * To run a query within a React component, call `useGetErrorReportingConsent` and pass it any options that fit your needs.
 * When your component renders, `useGetErrorReportingConsent` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetErrorReportingConsent({
 *   variables: {
 *   },
 * });
 */
export function useGetErrorReportingConsent(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GetErrorReportingConsent,
    GetErrorReportingConsentVariables
  >
) {
  return ApolloReactHooks.useQuery<GetErrorReportingConsent, GetErrorReportingConsentVariables>(
    GetErrorReportingConsentDocument,
    baseOptions
  );
}
export function useGetErrorReportingConsentLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetErrorReportingConsent,
    GetErrorReportingConsentVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetErrorReportingConsent, GetErrorReportingConsentVariables>(
    GetErrorReportingConsentDocument,
    baseOptions
  );
}
export type GetErrorReportingConsentHookResult = ReturnType<typeof useGetErrorReportingConsent>;
export type GetErrorReportingConsentLazyQueryHookResult = ReturnType<
  typeof useGetErrorReportingConsentLazyQuery
>;
export type GetErrorReportingConsentQueryResult = ApolloReactCommon.QueryResult<
  GetErrorReportingConsent,
  GetErrorReportingConsentVariables
>;
