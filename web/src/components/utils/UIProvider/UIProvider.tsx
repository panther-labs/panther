import React from 'react';
import { SnackbarProvider, ThemeProvider } from 'pouncejs';
import { SidesheetManager, SidesheetProvider } from 'Components/utils/Sidesheet';
import { ModalManager, ModalProvider } from 'Components/utils/Modal';

// Helper that allows us to guarantee same core providers in production & testing environments
const UIProvider: React.FC = ({ children }) => (
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

export default UIProvider;
