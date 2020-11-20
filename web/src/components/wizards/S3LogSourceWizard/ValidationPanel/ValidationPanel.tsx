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
import { AbstractButton, Button, Flex, Img, Link, Text } from 'pouncejs';
import { useFormikContext } from 'formik';
import FailureStatus from 'Assets/statuses/failure.svg';
import WaitingStatus from 'Assets/statuses/waiting.svg';
import SuccessStatus from 'Assets/statuses/success.svg';
import RealTimeNotication from 'Assets/statuses/real-time-notification.svg';
import urls from 'Source/urls';
import LinkButton from 'Components/buttons/LinkButton';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { extractErrorMessage } from 'Helpers/utils';
import { ApolloError } from '@apollo/client';
import { LOG_ONBOARDING_SNS_DOC_URL } from 'Source/constants';
import { S3LogSourceWizardValues } from '../S3LogSourceWizard';

const ValidationPanel: React.FC = () => {
  const [errorMessage, setErrorMessage] = React.useState('');
  const { reset: resetWizard, currentStepStatus, setCurrentStepStatus } = useWizardContext();
  const { initialValues, submitForm, resetForm } = useFormikContext<S3LogSourceWizardValues>();
  const [shouldShowNotificationsScreen, setNotificationScreenVisibility] = React.useState(
    !initialValues.integrationId
  );

  React.useEffect(() => {
    (async () => {
      try {
        await submitForm();
        setErrorMessage('');
        setCurrentStepStatus('PASSING');
      } catch (err) {
        setErrorMessage(extractErrorMessage(err as ApolloError));
        setCurrentStepStatus('FAILING');
      }
    })();
  }, []);

  if (currentStepStatus === 'PENDING') {
    return (
      <WizardPanel>
        <Flex align="center" direction="column" mx="auto">
          <WizardPanel.Heading
            title="Almost There!"
            subtitle="We are just making sure that everything is setup correctly. Hold on tight..."
          />
          <Img
            nativeWidth={120}
            nativeHeight={120}
            alt="Validating source health..."
            src={WaitingStatus}
          />
        </Flex>
      </WizardPanel>
    );
  }

  if (currentStepStatus === 'FAILING') {
    return (
      <WizardPanel>
        <Flex align="center" direction="column" mx="auto">
          <WizardPanel.Heading title="Something didn't go as planned" subtitle={errorMessage} />
          <Img
            nativeWidth={120}
            nativeHeight={120}
            alt="Failed to verify source health"
            src={FailureStatus}
          />
          <WizardPanel.Actions>
            <Button onClick={resetWizard}>Start over</Button>
          </WizardPanel.Actions>
        </Flex>
      </WizardPanel>
    );
  }

  if (shouldShowNotificationsScreen) {
    return (
      <WizardPanel>
        <Flex align="center" direction="column" mx="auto" width={600}>
          <WizardPanel.Heading
            title="Adding Notifications for New Data"
            subtitle={[
              'You can now follow the ',
              <Link key={0} external href={LOG_ONBOARDING_SNS_DOC_URL}>
                steps found here
              </Link>,
              ' to notify Panther',
              <br key={1} />,
              'when new data becomes available for analysis.',
            ]}
          />
          <Img nativeWidth={120} nativeHeight={120} alt="Bell" src={RealTimeNotication} />
          <WizardPanel.Actions>
            <Button onClick={() => setNotificationScreenVisibility(false)}>
              I Have Setup Notifications
            </Button>
          </WizardPanel.Actions>
          <Text fontSize="medium" color="gray-300" textAlign="center" mb={4}>
            Panther does not validate if you{"'"}ve added SNS notifications to your S3 bucket.
            Failing to do this, will not allow Panther to reach your logs
          </Text>
        </Flex>
      </WizardPanel>
    );
  }

  return (
    <WizardPanel>
      <Flex align="center" direction="column" mx="auto" width={375}>
        <WizardPanel.Heading
          title="Everything looks good!"
          subtitle={
            initialValues.integrationId
              ? 'Your stack was successfully updated'
              : 'Your configured stack was deployed successfully and Panther now has permissions to pull data!'
          }
        />
        <Img
          nativeWidth={120}
          nativeHeight={120}
          alt="Stack deployed successfully"
          src={SuccessStatus}
        />
        <WizardPanel.Actions>
          <Flex direction="column" spacing={4}>
            <LinkButton to={urls.logAnalysis.sources.list()}>Finish Setup</LinkButton>
            {!initialValues.integrationId && (
              <Link
                as={AbstractButton}
                variant="discreet"
                onClick={() => {
                  resetForm();
                  resetWizard();
                }}
              >
                Add Another
              </Link>
            )}
          </Flex>
        </WizardPanel.Actions>
      </Flex>
    </WizardPanel>
  );
};

export default ValidationPanel;
