/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Box, Button, Flex } from 'pouncejs';
import { useWizardContext } from './WizardContext';

interface WizardPanelWrapperAction {
  disabled?: boolean;
}

interface WizardPanelWrapperComposition {
  Content: React.FC;
  Actions: React.FC;
  ActionNext: React.FC<WizardPanelWrapperAction>;
  ActionPrev: React.FC<WizardPanelWrapperAction>;
}

const WizardPanelWrapper: React.FC & WizardPanelWrapperComposition = ({ children }) => {
  return (
    <Flex minHeight={550} flexDirection="column">
      {children}
    </Flex>
  );
};

const WizardPanelWrapperContent: React.FC = ({ children }) => {
  return (
    <Box width={600} m="auto">
      {children}
    </Box>
  );
};

const WizardPanelWrapperActions: React.FC = ({ children }) => {
  return <Flex justifyContent="flex-end">{children}</Flex>;
};

const WizardPanelActionPrev: React.FC<WizardPanelWrapperAction> = ({ disabled }) => {
  const { goToPrevStep } = useWizardContext();
  return (
    <Button size="large" variant="default" onClick={goToPrevStep} mr={3} disabled={disabled}>
      Back
    </Button>
  );
};

const WizardPanelActionNext: React.FC<WizardPanelWrapperAction> = ({ disabled }) => {
  const { goToNextStep } = useWizardContext();
  return (
    <Button size="large" variant="primary" onClick={goToNextStep} disabled={disabled}>
      Next
    </Button>
  );
};

WizardPanelWrapper.Content = React.memo(WizardPanelWrapperContent);
WizardPanelWrapper.Actions = React.memo(WizardPanelWrapperActions);
WizardPanelWrapper.ActionPrev = React.memo(WizardPanelActionPrev);
WizardPanelWrapper.ActionNext = React.memo(WizardPanelActionNext);

export default WizardPanelWrapper;
