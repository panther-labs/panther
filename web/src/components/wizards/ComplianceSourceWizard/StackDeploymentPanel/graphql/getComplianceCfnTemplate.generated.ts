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

import * as Types from '../../../../../../__generated__/schema';

import { GraphQLError } from 'graphql';
import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetComplianceCfnTemplateVariables = {
  input: Types.GetComplianceIntegrationTemplateInput;
};

export type GetComplianceCfnTemplate = {
  getComplianceIntegrationTemplate: Pick<Types.IntegrationTemplate, 'body' | 'stackName'>;
};

export const GetComplianceCfnTemplateDocument = gql`
  query GetComplianceCfnTemplate($input: GetComplianceIntegrationTemplateInput!) {
    getComplianceIntegrationTemplate(input: $input) {
      body
      stackName
    }
  }
`;

/**
 * __useGetComplianceCfnTemplate__
 *
 * To run a query within a React component, call `useGetComplianceCfnTemplate` and pass it any options that fit your needs.
 * When your component renders, `useGetComplianceCfnTemplate` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetComplianceCfnTemplate({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetComplianceCfnTemplate(
  baseOptions?: ApolloReactHooks.QueryHookOptions<
    GetComplianceCfnTemplate,
    GetComplianceCfnTemplateVariables
  >
) {
  return ApolloReactHooks.useQuery<GetComplianceCfnTemplate, GetComplianceCfnTemplateVariables>(
    GetComplianceCfnTemplateDocument,
    baseOptions
  );
}
export function useGetComplianceCfnTemplateLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<
    GetComplianceCfnTemplate,
    GetComplianceCfnTemplateVariables
  >
) {
  return ApolloReactHooks.useLazyQuery<GetComplianceCfnTemplate, GetComplianceCfnTemplateVariables>(
    GetComplianceCfnTemplateDocument,
    baseOptions
  );
}
export type GetComplianceCfnTemplateHookResult = ReturnType<typeof useGetComplianceCfnTemplate>;
export type GetComplianceCfnTemplateLazyQueryHookResult = ReturnType<
  typeof useGetComplianceCfnTemplateLazyQuery
>;
export type GetComplianceCfnTemplateQueryResult = ApolloReactCommon.QueryResult<
  GetComplianceCfnTemplate,
  GetComplianceCfnTemplateVariables
>;
export function mockGetComplianceCfnTemplate({
  data,
  variables,
  errors,
}: {
  data: GetComplianceCfnTemplate;
  variables?: GetComplianceCfnTemplateVariables;
  errors?: GraphQLError[];
}) {
  return {
    request: { query: GetComplianceCfnTemplateDocument, variables },
    result: { data, errors },
  };
}
