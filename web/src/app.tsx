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
import { Router } from 'react-router-dom';
import Routes from 'Source/routes';
import { History } from 'history';
import { ApolloProvider } from '@apollo/client';
import useHiddenOutline from 'Hooks/useHiddenOutline';
import { AuthProvider } from 'Components/utils/AuthContext';
import UIProviders from 'Components/utils/UIProviders';
import ErrorBoundary from 'Components/ErrorBoundary';
import { createApolloClient } from 'Source/apollo';

interface AppProps {
  history: History;
}

const App: React.FC<AppProps> = ({ history }) => {
  useHiddenOutline();

  const client = React.useMemo(() => createApolloClient(history), [history]);
  return (
    <ErrorBoundary fallbackStrategy="passthrough">
      <ApolloProvider client={client}>
        <AuthProvider>
          <Router history={history}>
            <UIProviders>
              <Routes />
            </UIProviders>
          </Router>
        </AuthProvider>
      </ApolloProvider>
    </ErrorBoundary>
  );
};

export default App;
