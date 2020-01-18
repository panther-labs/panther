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
import { WizardRenderStepParams } from 'Components/wizard';
import { Box, Button, Flex } from 'pouncejs';

interface PanelWrapperWizardActionsProps {
  goToPrevStep?: WizardRenderStepParams<{}>['goToPrevStep'];
  goToNextStep?: WizardRenderStepParams<{}>['goToNextStep'];
  isNextStepDisabled?: boolean;
  isPrevStepDisabled?: boolean;
}

interface PanelWrapperComposition {
  WizardActions: React.FC<PanelWrapperWizardActionsProps>;
  Content: React.FC;
}

const PanelWrapper: React.FC & PanelWrapperComposition = ({ children }) => {
  return (
    <Flex minHeight={550} flexDirection="column">
      {children}
    </Flex>
  );
};

const PanelWrapperContent: React.FC = ({ children }) => {
  return (
    <Box width={600} m="auto">
      {children}
    </Box>
  );
};

const PanelWrapperWizardActions: React.FC<PanelWrapperWizardActionsProps> = ({
  isNextStepDisabled,
  isPrevStepDisabled,
  goToPrevStep,
  goToNextStep,
}) => {
  return (
    <Flex justifyContent="flex-end">
      {goToPrevStep && (
        <Button
          size="large"
          variant="default"
          onClick={goToPrevStep}
          mr={3}
          disabled={isPrevStepDisabled}
        >
          Back
        </Button>
      )}
      {goToNextStep && (
        <Button size="large" variant="primary" onClick={goToNextStep} disabled={isNextStepDisabled}>
          Next
        </Button>
      )}
    </Flex>
  );
};

PanelWrapper.Content = PanelWrapperContent;
PanelWrapper.WizardActions = PanelWrapperWizardActions;

export default PanelWrapper;
