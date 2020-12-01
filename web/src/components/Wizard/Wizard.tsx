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

import React, { ReactElement, ReactNode } from 'react';
import { Box, Flex, Icon, Text, Divider, Card, BoxProps, IconProps } from 'pouncejs';
import { WizardContext } from './WizardContext';

interface WizardProps<Data> {
  children?: ReactNode;
  header?: boolean;
  initialData?: Data;
}

export type StepStatus = 'PASSING' | 'FAILING' | 'PENDING';

function Wizard<WizardData = any>({
  children,
  header = true,
  initialData = undefined,
}: WizardProps<WizardData>): ReactElement {
  const [currentStepIndex, setCurrentStepIndex] = React.useState(0);
  const [currentStepStatus, setCurrentStepStatus] = React.useState<StepStatus>('PENDING');
  const [wizardData, setWizardData] = React.useState<WizardData>(initialData);
  const prevStepIndex = React.useRef<number>(null);

  const steps = React.useMemo(() => React.Children.toArray(children) as React.ReactElement[], [
    children,
  ]);

  /**
   * Reset the step status everytime the step changes
   */
  React.useEffect(() => {
    setCurrentStepStatus('PENDING');
  }, [currentStepIndex, setCurrentStepStatus]);

  /**
   * Goes to the the chosen wizard step
   */
  const goToStep = React.useCallback(
    (stepIndex: number) => {
      prevStepIndex.current = stepIndex > currentStepIndex ? currentStepIndex : stepIndex - 1;
      setCurrentStepIndex(stepIndex);
    },
    [currentStepIndex]
  );

  /*
   * Resets the data to  the original value
   */
  const resetWizardData = React.useCallback(() => {
    setWizardData(initialData);
  }, [initialData, setWizardData]);

  /*
   *  Merges new data with the existing wizard data
   */
  const updateWizardData = React.useCallback(
    (data: WizardData) => {
      setWizardData({ ...wizardData, ...data });
    },
    [wizardData, setWizardData]
  );

  /**
   * Goes to the previous wizard step
   */
  const goToPrevStep = React.useCallback(() => {
    if (prevStepIndex.current >= 0) {
      goToStep(prevStepIndex.current);
    }
  }, [goToStep, prevStepIndex]);

  /**
   * Goes to the next wizard step
   */
  const goToNextStep = React.useCallback(() => {
    if (currentStepIndex < steps.length - 1) {
      goToStep(currentStepIndex + 1);
    }
  }, [goToStep, currentStepIndex]);

  /**
   * Fully resets the wizard,  including data and current step
   */
  const resetWizard = React.useCallback(() => {
    resetWizardData();
    setCurrentStepIndex(0);
    setCurrentStepStatus('PENDING');
  }, [resetWizardData, setCurrentStepIndex, setCurrentStepStatus]);

  /*
   * Exposes handlers to any components below
   */
  const contextValue = React.useMemo(
    () => ({
      goToStep,
      goToPrevStep,
      goToNextStep,
      resetData: resetWizardData,
      setData: setWizardData,
      updateData: updateWizardData,
      reset: resetWizard,
      data: wizardData,
      currentStepStatus,
      setCurrentStepStatus,
    }),
    [
      goToStep,
      goToPrevStep,
      goToNextStep,
      wizardData,
      currentStepStatus,
      resetWizardData,
      setWizardData,
      updateWizardData,
      setCurrentStepStatus,
    ]
  );

  return (
    <Card p={6} mb={6} as="article" width={1} position="relative">
      {header && (
        <Flex as="ul" justify="center" pt="10px" mb={60} zIndex={2}>
          {steps.map((step, index) => {
            const isLast = index === steps.length - 1;
            const isComplete = currentStepIndex > index;
            const isCurrent = currentStepIndex === index;
            const isPassing = currentStepStatus === 'PASSING';
            const isFailing = currentStepStatus === 'FAILING';

            let backgroundColor: BoxProps['backgroundColor'];
            let borderColor: BoxProps['borderColor'];
            let svgIcon: IconProps['type'];

            if (isComplete || isPassing) {
              backgroundColor = 'blue-400';
              borderColor = 'blue-400';
              svgIcon = 'check';
            } else if (isFailing) {
              backgroundColor = 'pink-600';
              borderColor = 'pink-600';
              svgIcon = 'alert-circle';
            } else {
              backgroundColor = 'transparent';
              borderColor = 'gray-300';
              svgIcon = null;
            }

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
                  borderColor={borderColor}
                  backgroundColor={backgroundColor}
                >
                  {svgIcon ? <Icon type={svgIcon} size="x-small" /> : index + 1}
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
      <Box pt={3}>
        <WizardContext.Provider value={contextValue}>
          {steps[currentStepIndex]}
        </WizardContext.Provider>
      </Box>
    </Card>
  );
}

interface WizardStepProps {
  title?: string;
}

const WizardStep: React.FC<WizardStepProps> = ({ children }) => children as React.ReactElement;
Wizard.Step = React.memo(WizardStep) as React.FC<WizardStepProps>;

export default Wizard;
