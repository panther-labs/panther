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

import { GeneralSettingsFull } from '../../../graphql/fragments/GeneralSettingsFull.generated';
import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetGeneralSettingsVariables = {};

export type GetGeneralSettings = { generalSettings: GeneralSettingsFull };

export const GetGeneralSettingsDocument = gql`
  query GetGeneralSettings {
    generalSettings {
      ...GeneralSettingsFull
    }
  }
  ${GeneralSettingsFull}
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
export function mockGetGeneralSettings({
  data,
  variables,
  errors,
}: {
  data: GetGeneralSettings;
  variables?: GetGeneralSettingsVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetGeneralSettingsDocument, variables },
    result: { data, errors },
  };
}
