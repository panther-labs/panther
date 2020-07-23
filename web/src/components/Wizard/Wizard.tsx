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
import { Box, Flex, IconProps, Icon, ProgressBar, Theme, SimpleGrid, Heading } from 'pouncejs';
import { WizardContext } from './WizardContext';

export interface WizardStepProps {
  title?: string;
  icon: IconProps['type'];
}

interface WizardComposition {
  Step: React.FC<WizardStepProps>;
}

const Wizard: React.FC & WizardComposition = ({ children }) => {
  const [currentStepIndex, setCurrentStepIndex] = React.useState(0);

  const steps = React.useMemo(() => React.Children.toArray(children) as React.ReactElement[], [
    children,
  ]);

  /**
   * Goes to the previous wizard step
   */
  const goToPrevStep = React.useCallback(() => {
    if (currentStepIndex > 0) {
      setCurrentStepIndex(currentStepIndex - 1);
    }
  }, [currentStepIndex]);

  /**
   * Goes to the next wizard step
   */
  const goToNextStep = React.useCallback(() => {
    if (currentStepIndex < steps.length - 1) {
      setCurrentStepIndex(currentStepIndex + 1);
    }
  }, [currentStepIndex]);

  /*
   * Exposes handlers to any components below
   */
  const contextValue = React.useMemo(
    () => ({
      goToPrevStep,
      goToNextStep,
    }),
    [goToPrevStep, goToNextStep]
  );

  return (
    <Box as="article" width={1}>
      <Box position="relative" mb={6}>
        <Box
          position="absolute"
          bottom={17}
          width={(steps.length - 1) / steps.length}
          ml={`${100 / (steps.length * 2)}%`}
        >
          <ProgressBar color="teal-500" progress={currentStepIndex / (steps.length - 1)} />
        </Box>
        <SimpleGrid as="ul" columns={steps.length} width={1} zIndex={2}>
          {steps.map((step, index) => {
            const isComplete = currentStepIndex > index || currentStepIndex === steps.length - 1;

            let labelColor: keyof Theme['colors'] = 'gray-500';
            if (currentStepIndex === index) {
              labelColor = 'gray-200';
            }
            if (isComplete) {
              labelColor = 'teal-500';
            }

            return (
              <Flex
                as="li"
                justify="center"
                align="center"
                direction="column"
                key={step.props.title}
                zIndex={2}
              >
                <Heading as="h3" color={labelColor} size="x-small" mb={4}>
                  {index + 1}. {step.props.title}
                </Heading>
                <Flex
                  borderRadius="circle"
                  justify="center"
                  align="center"
                  width={40}
                  height={40}
                  backgroundColor={isComplete ? 'teal-500' : 'navyblue-300'}
                >
                  <Icon type={isComplete ? 'check' : step.props.icon} size="small" />
                </Flex>
              </Flex>
            );
          })}
        </SimpleGrid>
      </Box>
      <Box>
        <WizardContext.Provider value={contextValue}>
          {steps[currentStepIndex]}
        </WizardContext.Provider>
      </Box>
    </Box>
  );
};

export const WizardStep: React.FC<WizardStepProps> = ({ children }) =>
  children as React.ReactElement;

Wizard.Step = React.memo(WizardStep);

export default Wizard;
