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
import { CLOUD_SECURITY_REAL_TIME_DOC_URL } from 'Source/constants';
import LinkButton from 'Components/buttons/LinkButton';
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { extractErrorMessage } from 'Helpers/utils';
import { ApolloError } from '@apollo/client';
import { ComplianceSourceWizardValues } from '../ComplianceSourceWizard';

const ValidationPanel: React.FC = () => {
  const { reset: resetWizard, currentStepStatus, setCurrentStepStatus } = useWizardContext();
  const { initialValues, submitForm, resetForm, values } = useFormikContext<
    ComplianceSourceWizardValues
  >();
  const [errorMessage, setErrorMessage] = React.useState('');
  const [shouldShowRealTimeScreen, setRealTimeScreenVisibility] = React.useState(
    // creating a source with Real-time enabled
    (!initialValues.integrationId && values.cweEnabled) ||
      // updating a source to enable real-time
      (!initialValues.cweEnabled && values.cweEnabled)
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

  if (shouldShowRealTimeScreen) {
    return (
      <WizardPanel>
        <Flex align="center" direction="column" mx="auto" width={600}>
          <WizardPanel.Heading
            title="Configuring Real-Time Monitoring"
            subtitle={[
              'You can now follow the ',
              <Link key={0} external href={CLOUD_SECURITY_REAL_TIME_DOC_URL}>
                steps found here
              </Link>,
              ' to let Panther',
              <br key={1} />,
              'monitor your AWS Account in real-time',
            ]}
          />
          <Img nativeWidth={120} nativeHeight={120} alt="Bell" src={RealTimeNotication} />
          <WizardPanel.Actions>
            <Button onClick={() => setRealTimeScreenVisibility(false)}>
              I Have Setup Real-Time
            </Button>
          </WizardPanel.Actions>
          <Text fontSize="medium" color="gray-300" textAlign="center" mb={4}>
            Panther does not validate if you{"'"}ve configured Real-Time monitoring in your AWS
            Account. Failing to do this, will not allow Panther to receive real-time Cloudwatch
            Events
          </Text>
        </Flex>
      </WizardPanel>
    );
  }

  return (
    <WizardPanel>
      <Flex align="center" direction="column" mx="auto" width={350}>
        <WizardPanel.Heading
          title="Everything looks good!"
          subtitle={
            initialValues.integrationId
              ? 'Your stack was successfully updated'
              : 'Your configured stack was deployed successfully and your source’s setup is now complete!'
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
            <LinkButton to={urls.integrations.cloudAccounts.list()}>Finish Setup</LinkButton>
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
