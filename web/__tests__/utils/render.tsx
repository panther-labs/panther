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
import { AuthContext, UserInfo } from 'Components/utils/AuthContext';
import { createMemoryHistory } from 'history';
import { Router } from 'react-router-dom';
import UIProviders from 'Components/utils/UIProviders';
import * as customQueries from './queries';
import { buildUserInfo, mockAuthProviderValue } from './auth';

interface RenderOptions extends Omit<RtlRenderOptions, 'queries'> {
  /**
   * The initial route that the underlying React Router will be in
   * @default "/"
   * */
  initialRoute?: string;

  /**
   * The information for the authenticated user. Pass `null` or  `false` if you don't want to have
   * the user as authenticated in your tests
   * @default  the output of `buildUserInfo()`
   */
  userInfo?: UserInfo;

  /**
   * A list of GraphQL requests along with  their mocked results
   * https://www.apollographql.com/docs/react/v3.0-beta/development-testing/testing/
   */
  mocks?: readonly MockedResponse[];
}

export const render = (element: React.ReactElement, options: RenderOptions = {}) => {
  const { initialRoute = '/', userInfo = buildUserInfo(), mocks, ...rtlOptions } = options;

  const history = createMemoryHistory({ initialEntries: [initialRoute] });
  const authProviderValue = mockAuthProviderValue(userInfo);

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
          <UIProviders>
            <header id="main-header" />
            {element}
            <footer id="footer"></footer>
          </UIProviders>
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
    ...authProviderValue,
    ...rtlRenderResult,
  };
};
