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
import { SnackbarProvider, ThemeProvider } from 'pouncejs';
import { SidesheetManager, SidesheetProvider } from 'Components/utils/Sidesheet';
import { ModalManager, ModalProvider } from 'Components/utils/Modal';

// Helper that allows us to guarantee same core providers in production & testing environments
const UIProviders: React.FC = ({ children }) => (
  <ThemeProvider>
    <SidesheetProvider>
      <ModalProvider>
        <SnackbarProvider>
          {children}
          <ModalManager />
          <SidesheetManager />
        </SnackbarProvider>
      </ModalProvider>
    </SidesheetProvider>
  </ThemeProvider>
);

export default UIProviders;
