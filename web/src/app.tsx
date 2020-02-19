/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { SnackbarProvider, ThemeProvider } from 'pouncejs';
import { Router } from 'react-router-dom';
import Routes from 'Source/routes';
import { History } from 'history';
import { ApolloProvider } from '@apollo/client';
import { AuthProvider } from 'Components/utils/auth-context';
import PromptController from 'Components/utils/prompt-controller';
import { ModalProvider } from 'Components/utils/modal-context';
import { SidesheetProvider } from 'Components/utils/sidesheet-context';
import ModalManager from 'Components/utils/modal-manager';
import SidesheetManager from 'Components/utils/sidesheet-manager';
import ErrorBoundary from 'Components/error-boundary';
import createApolloClient from 'Source/client';

interface AppProps {
  history: History;
}
const App: React.FC<AppProps> = ({ history }) => {
  const client = React.useMemo(() => createApolloClient(history), [history]);
  return (
    <ErrorBoundary fallbackStrategy="passthrough">
      <ApolloProvider client={client}>
        <AuthProvider>
          <ThemeProvider>
            <Router history={history}>
              <SidesheetProvider>
                <ModalProvider>
                  <SnackbarProvider>
                    <Routes />
                    <ModalManager />
                    <SidesheetManager />
                    <PromptController />
                  </SnackbarProvider>
                </ModalProvider>
              </SidesheetProvider>
            </Router>
          </ThemeProvider>
        </AuthProvider>
      </ApolloProvider>
    </ErrorBoundary>
  );
};

export default App;
