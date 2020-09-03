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
import { useWizardContext, WizardPanel } from 'Components/Wizard';
import { Button, Text, Link, Img, Flex, Box, AbstractButton } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import SuccessStatus from 'Assets/statuses/success.svg';
import FailureStatus from 'Assets/statuses/failure.svg';
import NotificationStatus from 'Assets/statuses/notification.svg';
import { WizardData as CreateWizardData } from '../../CreateDestinationWizard';
import { WizardData as EditWizardData } from '../../EditDestinationWizard';
import { useSendTestAlertLazyQuery } from './graphql/sendTestAlert.generated';

type TestStatus = 'PASSED' | 'FAILED' | null;

const DestinationTestPanel: React.FC = () => {
  const [testStatus, setTestStatus] = React.useState<TestStatus>(null);
  const {
    data: { destination },
    reset,
    goToPrevStep,
  } = useWizardContext<CreateWizardData & EditWizardData>();

  const [sendTestAlert, { loading }] = useSendTestAlertLazyQuery({
    fetchPolicy: 'network-only', // Don't use cache
    variables: {
      input: {
        outputIds: [destination.outputId],
      },
    },
    onCompleted: () => setTestStatus('PASSED'),
    onError: () => setTestStatus('FAILED'),
  });

  const handleTestAlertClick = React.useCallback(() => {
    sendTestAlert();
  }, []);

  if (testStatus === 'FAILED') {
    return (
      <Box maxWidth={700} mx="auto">
        <WizardPanel.Heading
          title="Testing your Destination"
          subtitle="Something went wrong and the destination you have configured did not receive the test alert. Please update your destination settings and try again."
        />
        <Flex direction="column" align="center" spacing={6} my={6}>
          <Img
            nativeWidth={120}
            nativeHeight={120}
            alt="Test Alert failed to receive"
            src={FailureStatus}
          />
          <Text mb={5}>
            If you don{"'"}t feel like it right now, you can always change the configuration later
          </Text>
          <Link as={RRLink} mb={6} to={urls.settings.destinations.edit(destination.outputId)}>
            <Button as="div" onClick={goToPrevStep}>
              Back to Configuration
            </Button>
          </Link>
          <Link as={RRLink} variant="discreet" to={urls.settings.destinations.list()}>
            Skip Testing
          </Link>
        </Flex>
      </Box>
    );
  }

  if (testStatus === 'PASSED') {
    return (
      <Box maxWidth={700} mx="auto">
        <WizardPanel.Heading
          title="Testing your Destination"
          subtitle="Everything worked as planned and your destination received the triggered alert. You can always send additional test alerts from the destinations page."
        />
        <Flex direction="column" align="center" spacing={6} my={6}>
          <Img
            nativeWidth={120}
            nativeHeight={120}
            alt="Test Alert received"
            src={NotificationStatus}
          />
          <Text mb={5}>Signed, sealed, and delivered. You are good to go!</Text>
          <Link as={RRLink} mb={6} to={urls.settings.destinations.list()}>
            <Button as="div">Finish Setup</Button>
          </Link>
          <Link as={AbstractButton} variant="discreet" onClick={reset}>
            Add Another
          </Link>
        </Flex>
      </Box>
    );
  }

  return (
    <Box maxWidth={700} mx="auto">
      <WizardPanel.Heading
        title="Everything looks good!"
        subtitle="Your destination was successfully added and you will receive alerts based on your configuration. You can always edit or delete this destination from the destinations page"
      />
      <Flex direction="column" align="center" spacing={6} my={6}>
        <Img nativeWidth={120} nativeHeight={120} alt="Success" src={SuccessStatus} />
        <Text mb={5}>Do you want to try it out by sending a test Alert?</Text>
        <Box>
          <Button loading={loading} disabled={loading} onClick={handleTestAlertClick}>
            Send Test Alert
          </Button>
        </Box>
        <Link as={RRLink} variant="discreet" to={urls.settings.destinations.list()}>
          Finish Setup
        </Link>
      </Flex>
    </Box>
  );
};

export default DestinationTestPanel;
