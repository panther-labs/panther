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
    <Flex minHeight={550} direction="column">
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
  return <Flex justify="flex-end">{children}</Flex>;
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
