import React from 'react';

interface WizardContextValue {
  goToPrevStep: () => void;
  goToNextStep: () => void;
}

export const WizardContext = React.createContext<WizardContextValue>(null);

export const useWizardContext = () => React.useContext(WizardContext);
