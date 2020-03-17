/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetComplianceCfnTemplateVariables = {
  input: Types.GetComplianceIntegrationTemplateInput;
};

export type GetComplianceCfnTemplate = {
  getComplianceIntegrationTemplate: Pick<Types.IntegrationTemplate, 'body'>;
};

export const GetComplianceCfnTemplateDocument = gql`
  query GetComplianceCfnTemplate($input: GetComplianceIntegrationTemplateInput!) {
    getComplianceIntegrationTemplate(input: $input) {
      body
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
