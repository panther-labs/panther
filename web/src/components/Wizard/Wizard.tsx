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
import { Box, Flex, Icon, Text, Divider, Card } from 'pouncejs';
import { WizardContext } from './WizardContext';

export interface WizardStepProps {
  title?: string;
}

interface WizardProps {
  header?: boolean;
}

interface WizardComposition {
  Step: React.FC<WizardStepProps>;
}

const Wizard: React.FC<WizardProps> & WizardComposition = ({ children, header = true }) => {
  const [currentStepIndex, setCurrentStepIndex] = React.useState(0);
  const prevStepIndex = React.useRef<number>(null);
  const stepContext = React.useRef<any>(null);

  const steps = React.useMemo(() => React.Children.toArray(children) as React.ReactElement[], [
    children,
  ]);

  /**
   * Goes to the the chosen wizard step
   */
  const goToStep = React.useCallback(
    (stepIndex, context?: any) => {
      stepContext.current = context !== undefined ? context : null;
      prevStepIndex.current = stepIndex > currentStepIndex ? currentStepIndex : stepIndex - 1;
      setCurrentStepIndex(stepIndex);
    },
    [currentStepIndex]
  );

  /**
   * Goes to the previous wizard step
   */
  const goToPrevStep = React.useCallback(
    (context?: any) => {
      if (prevStepIndex.current >= 0) {
        goToStep(prevStepIndex.current, context);
      }
    },
    [prevStepIndex]
  );

  /**
   * Goes to the next wizard step
   */
  const goToNextStep = React.useCallback(
    (context?: any) => {
      if (currentStepIndex < steps.length - 1) {
        goToStep(currentStepIndex + 1, context);
      }
    },
    [currentStepIndex]
  );

  /*
   * Exposes handlers to any components below
   */
  const contextValue = React.useMemo(
    () => ({
      goToPrevStep,
      goToNextStep,
      stepContext: stepContext.current,
    }),
    [goToPrevStep, goToNextStep, stepContext]
  );

  return (
    <Card p={6} mb={6} as="article" width={1}>
      {header && (
        <Flex as="ul" justify="center" pt="10px" zIndex={2}>
          {steps.map((step, index) => {
            const isLast = index === steps.length - 1;
            const isComplete = currentStepIndex > index || currentStepIndex === steps.length - 1;
            const isCurrent = currentStepIndex === index;

            return (
              <Flex
                as="li"
                justify="center"
                align="center"
                key={step.props.title}
                zIndex={2}
                opacity={isComplete || isCurrent ? 1 : 0.3}
              >
                <Flex
                  justify="center"
                  align="center"
                  width={25}
                  height={25}
                  fontSize="small"
                  fontWeight="bold"
                  borderRadius="circle"
                  border="1px solid"
                  borderColor={isComplete ? 'blue-400' : 'gray-300'}
                  backgroundColor={isComplete ? 'blue-400' : 'transparent'}
                >
                  {isComplete ? <Icon type="check" size="x-small" /> : index + 1}
                </Flex>
                <Text fontSize="medium" ml={2}>
                  {step.props.title}
                </Text>
                {!isLast && <Divider width={64} mx={4} />}
              </Flex>
            );
          })}
        </Flex>
      )}
      <Box position="relative" pt={3}>
        <WizardContext.Provider value={contextValue}>
          {steps[currentStepIndex]}
        </WizardContext.Provider>
      </Box>
    </Card>
  );
};

export const WizardStep: React.FC<WizardStepProps> = ({ children }) =>
  children as React.ReactElement;

Wizard.Step = React.memo(WizardStep);

export default Wizard;
