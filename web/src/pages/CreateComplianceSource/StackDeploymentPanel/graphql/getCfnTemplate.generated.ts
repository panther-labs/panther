/* eslint-disable import/order, import/no-duplicates */
import * as Types from '../../../../../__generated__/schema';

import gql from 'graphql-tag';
import * as ApolloReactCommon from '@apollo/client';
import * as ApolloReactHooks from '@apollo/client';

export type GetCfnTemplateVariables = {
  input: Types.GetIntegrationTemplateInput;
};

export type GetCfnTemplate = { getIntegrationTemplate: Pick<Types.IntegrationTemplate, 'body'> };

export const GetCfnTemplateDocument = gql`
  query GetCfnTemplate($input: GetIntegrationTemplateInput!) {
    getIntegrationTemplate(input: $input) {
      body
    }
  }
`;

/**
 * __useGetCfnTemplate__
 *
 * To run a query within a React component, call `useGetCfnTemplate` and pass it any options that fit your needs.
 * When your component renders, `useGetCfnTemplate` returns an object from Apollo Client that contains loading, error, and data properties
 * you can use to render your UI.
 *
 * @param baseOptions options that will be passed into the query, supported options are listed on: https://www.apollographql.com/docs/react/api/react-hooks/#options;
 *
 * @example
 * const { data, loading, error } = useGetCfnTemplate({
 *   variables: {
 *      input: // value for 'input'
 *   },
 * });
 */
export function useGetCfnTemplate(
  baseOptions?: ApolloReactHooks.QueryHookOptions<GetCfnTemplate, GetCfnTemplateVariables>
) {
  return ApolloReactHooks.useQuery<GetCfnTemplate, GetCfnTemplateVariables>(
    GetCfnTemplateDocument,
    baseOptions
  );
}
export function useGetCfnTemplateLazyQuery(
  baseOptions?: ApolloReactHooks.LazyQueryHookOptions<GetCfnTemplate, GetCfnTemplateVariables>
) {
  return ApolloReactHooks.useLazyQuery<GetCfnTemplate, GetCfnTemplateVariables>(
    GetCfnTemplateDocument,
    baseOptions
  );
}
export type GetCfnTemplateHookResult = ReturnType<typeof useGetCfnTemplate>;
export type GetCfnTemplateLazyQueryHookResult = ReturnType<typeof useGetCfnTemplateLazyQuery>;
export type GetCfnTemplateQueryResult = ApolloReactCommon.QueryResult<
  GetCfnTemplate,
  GetCfnTemplateVariables
>;
