import React from 'react';
import {
  render as rtlRender,
  queries,
  RenderOptions as RtlRenderOptions,
} from '@testing-library/react';
import { ApolloLink, InMemoryCache } from '@apollo/client';
import { MockedProvider, MockLink, MockedResponse } from '@apollo/client/testing';
import cleanParamsLink from 'Source/apollo/cleanParamsLink';
import createErrorLink from 'Source/apollo/createErrorLink';
import typePolicies from 'Source/apollo/typePolicies';
import { AuthContext } from 'Components/utils/AuthContext';
import { createMemoryHistory } from 'history';
import { Router } from 'react-router-dom';
import UIProvider from 'Components/utils/UIProvider';
import * as customQueries from './queries';
import { mockAuthProviderValue } from './auth';

interface RenderOptions extends Omit<RtlRenderOptions, 'queries'> {
  /**
   * The initial route that the underlying React Router will be in
   * @default "/"
   * */
  initialRoute?: string;

  /**
   * Whether the test should have an authenticated user present
   * @default  true
   */
  isAuthenticated?: boolean;

  /**
   * A list of GraphQL requests along with  their mocked results
   * https://www.apollographql.com/docs/react/v3.0-beta/development-testing/testing/
   */
  mocks?: readonly MockedResponse[];
}

const render = (element: React.ReactElement, options: RenderOptions = {}) => {
  const { initialRoute = '/', isAuthenticated = true, mocks, ...rtlOptions } = options;

  const history = createMemoryHistory({ initialEntries: [initialRoute] });
  const authProviderValue = mockAuthProviderValue(isAuthenticated);

  // A mock terminating link that allows apollo to resolve graphql operations from the mocks
  const mockLink = new MockLink(mocks, true);

  // Recreate our normal Apollo link chain
  const apolloLink = ApolloLink.from([cleanParamsLink, createErrorLink(history), mockLink]);

  // Create a new Apollo cache with the same config as the production oone
  const apolloCache = new InMemoryCache({ typePolicies });

  const ui = (
    <MockedProvider link={apolloLink} cache={apolloCache}>
      <AuthContext.Provider value={authProviderValue}>
        <Router history={history}>
          <UIProvider>{element}</UIProvider>
        </Router>
      </AuthContext.Provider>
    </MockedProvider>
  );

  const rtlRenderResult = rtlRender(ui, {
    queries: { ...queries, ...customQueries },
    ...rtlOptions,
  });

  return {
    history,
    userInfo: authProviderValue.userInfo,
    ...rtlRenderResult,
  };
};

export { render };
export * from '@testing-library/react';
