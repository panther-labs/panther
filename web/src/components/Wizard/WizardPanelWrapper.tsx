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
import { Box, Button, FadeIn, Flex, Heading, IconButton, Text } from 'pouncejs';
import { useWizardContext } from './WizardContext';

interface WizardPanelWrapperAction {
  disabled?: boolean;
  retainContext?: boolean;
}

interface WizardPanelHeadingProps {
  title: string;
  subtitle?: string;
}

interface WizardPanelWrapperComposition {
  Content: React.FC;
  Actions: React.FC;
  ActionNext: React.FC<WizardPanelWrapperAction>;
  ActionPrev: React.FC<WizardPanelWrapperAction>;
  Heading: React.FC<WizardPanelHeadingProps>;
}

const WizardPanelWrapper: React.FC & WizardPanelWrapperComposition = ({ children }) => {
  return <Flex direction="column">{children}</Flex>;
};

const WizardPanelWrapperContent: React.FC = ({ children }) => {
  return (
    <Box width={700} mx="auto">
      <FadeIn>{children}</FadeIn>
    </Box>
  );
};

const WizardPanelHeading: React.FC<WizardPanelHeadingProps> = ({ title, subtitle }) => (
  <Box as="header" mb={10} textAlign="center">
    <Heading size="small" mb={2}>
      {title}
    </Heading>
    {!!subtitle && (
      <Text fontSize="medium" color="gray-300">
        {subtitle}
      </Text>
    )}
  </Box>
);

const WizardPanelWrapperActions: React.FC = ({ children }) => {
  return (
    <Flex justify="center" mt={8} mb={4}>
      {children}
    </Flex>
  );
};

const WizardPanelActionPrev: React.FC<WizardPanelWrapperAction> = ({
  disabled,
  retainContext = false,
}) => {
  const { goToPrevStep, stepContext } = useWizardContext();
  return (
    <Box position="absolute" top={0} left={0}>
      <IconButton
        disabled={disabled}
        icon="arrow-back"
        variantColor="navyblue"
        aria-label="Go back"
        onClick={() => goToPrevStep(retainContext ? stepContext : undefined)}
      />
    </Box>
  );
};

const WizardPanelActionNext: React.FC<WizardPanelWrapperAction> = ({
  disabled,
  children,
  retainContext = false,
}) => {
  const { goToNextStep, stepContext } = useWizardContext();
  return (
    <Button
      onClick={() => goToNextStep(retainContext ? stepContext : undefined)}
      disabled={disabled}
    >
      {children || 'Next'}
    </Button>
  );
};

WizardPanelWrapper.Content = React.memo(WizardPanelWrapperContent);
WizardPanelWrapper.Actions = React.memo(WizardPanelWrapperActions);
WizardPanelWrapper.ActionPrev = React.memo(WizardPanelActionPrev);
WizardPanelWrapper.ActionNext = React.memo(WizardPanelActionNext);
WizardPanelWrapper.Heading = React.memo(WizardPanelHeading);

export default WizardPanelWrapper;
