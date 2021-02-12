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
import { AbstractButton, Alert, Button, Flex, Img, Link, Text, Box } from 'pouncejs';
import { useFormikContext } from 'formik';
import FailureStatus from 'Assets/statuses/failure.svg';
import WaitingStatus from 'Assets/statuses/waiting.svg';
import SuccessStatus from 'Assets/statuses/success.svg';
import RealTimeNotification from 'Assets/statuses/real-time-notification.svg';
import urls from 'Source/urls';
import LinkButton from 'Components/buttons/LinkButton';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { extractErrorMessage } from 'Helpers/utils';
import { ApolloError } from '@apollo/client';
import { LOG_ONBOARDING_SNS_DOC_URL } from 'Source/constants';
import { AddS3LogSource } from 'Pages/CreateLogSource/CreateS3LogSource/graphql/addS3LogSource.generated';
import { UpdateS3LogSource } from 'Pages/EditS3LogSource/graphql/updateS3LogSource.generated';
import { S3LogIntegrationDetails } from 'Source/graphql/fragments/S3LogIntegrationDetails.generated';
import { S3LogSourceWizardValues } from '../S3LogSourceWizard';

type SubmitResult = {
  data: AddS3LogSource & UpdateS3LogSource;
};

function getResponseData(result: SubmitResult): S3LogIntegrationDetails {
  let castedResult;
  if (result?.data.addS3LogIntegration) {
    castedResult = result.data.addS3LogIntegration as S3LogIntegrationDetails;
  } else {
    castedResult = result.data.updateS3LogIntegration as S3LogIntegrationDetails;
  }
  return castedResult;
}

const ValidationPanel: React.FC = () => {
  const [errorMessage, setErrorMessage] = React.useState('');
  const { reset: resetWizard, currentStepStatus, setCurrentStepStatus } = useWizardContext();
  const { initialValues, submitForm, resetForm } = useFormikContext<S3LogSourceWizardValues>();
  const [shouldShowNotificationsScreen, setNotificationScreenVisibility] = React.useState(true);

  const [showManagedNotificationsWarning, setShowManagedNotificationsWarning] = React.useState(
    false
  );

  React.useEffect(() => {
    (async () => {
      try {
        const result = ((await submitForm()) as unknown) as SubmitResult;
        const { managedBucketNotifications, notificationsConfigurationSucceeded } = getResponseData(
          result
        );
        /* When this source is created or updated we need to check if user has selected to automate
         * setting up notifications, this can fail while the integration was successfully created
         * so we need to inform user if something went wrong so they can add them manually
         */
        if (managedBucketNotifications === true && notificationsConfigurationSucceeded === false) {
          setShowManagedNotificationsWarning(true);
        } else if (
          managedBucketNotifications === true &&
          notificationsConfigurationSucceeded === true
        ) {
          setShowManagedNotificationsWarning(false);
          // If there were successfully configure we dont need to show them
          // info about how they can set them up
          setNotificationScreenVisibility(false);
        }

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
          {showManagedNotificationsWarning && (
            <Box mb={6}>
              <Alert
                variant="warning"
                title={'Setting up managed notifications failed'}
                description={'Please set them up using the instructions below'}
              />
            </Box>
          )}
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
          <Img nativeWidth={120} nativeHeight={120} alt="Bell" src={RealTimeNotification} />
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
