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
import { Box, Flex, IconProps, Icon, Label, Grid, ProgressBar } from 'pouncejs';

export interface WizardRenderStepParams<T> {
  index: number;
  goToPrevStep: () => void;
  goToNextStep: () => void;
  wizardData: T;
  updateWizardData: (data: T) => void;
}

export interface WizardStep<T> {
  title?: string;
  icon: IconProps['type'];
  renderStep: (wizardParams: WizardRenderStepParams<T>) => React.ReactElement | null;
}

export interface WizardProps<T> {
  steps: WizardStep<T>[];
  initialData?: T;
  autoCompleteLastStep?: boolean;
}

function Wizard<T extends { [key: string]: any }>({
  steps,
  initialData = {} as T,
  autoCompleteLastStep = false,
}: WizardProps<T>): React.ReactElement {
  const [wizardData, setWizardData] = React.useState<T>(initialData);
  const [currentStepIndex, setCurrentStepIndex] = React.useState(0);

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

  /**
   * Adds data to the the total wizard data
   */
  const updateWizardData = React.useCallback(
    (newData: { [key: string]: any }) => {
      setWizardData({
        ...wizardData,
        ...newData,
      });
    },
    [wizardData]
  );

  return (
    <Box is="article" width={1}>
      <Box position="relative" mb={6}>
        <Box
          position="absolute"
          bottom={20}
          width={(steps.length - 1) / steps.length}
          ml={`${100 / (steps.length * 2)}%`}
        >
          <ProgressBar progressColor="green200" progress={currentStepIndex / (steps.length - 1)} />
        </Box>
        <Grid is="ul" gridTemplateColumns={`repeat(${steps.length}, 1fr)`} width={1} zIndex={2}>
          {steps.map((step, index) => {
            const isComplete =
              currentStepIndex > index ||
              (autoCompleteLastStep && currentStepIndex === steps.length - 1);

            let labelColor = 'grey100';
            if (currentStepIndex === index) {
              labelColor = 'grey400';
            }
            if (isComplete) {
              labelColor = 'green300';
            }

            return (
              <Flex
                is="li"
                justifyContent="center"
                alignItems="center"
                flexDirection="column"
                key={step.title}
                zIndex={2}
              >
                <Label is="h3" size="large" color={labelColor} mb={2}>
                  {index + 1}. {step.title}
                </Label>
                <Flex
                  borderRadius="circle"
                  justifyContent="center"
                  alignItems="center"
                  width={40}
                  height={40}
                  backgroundColor={isComplete ? 'green200' : 'grey50'}
                >
                  <Icon
                    type={isComplete ? 'check' : step.icon}
                    size="small"
                    color={isComplete ? 'white' : 'grey200'}
                  />
                </Flex>
              </Flex>
            );
          })}
        </Grid>
      </Box>
      <Box>
        {steps[currentStepIndex].renderStep({
          wizardData,
          index: currentStepIndex,
          goToPrevStep,
          goToNextStep,
          updateWizardData,
        })}
      </Box>
    </Box>
  );
}

export default Wizard;
