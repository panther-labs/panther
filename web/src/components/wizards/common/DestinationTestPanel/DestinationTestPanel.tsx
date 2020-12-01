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
import {
  AbstractButton,
  Box,
  Button,
  Card,
  Flex,
  Grid,
  Img,
  Link,
  Text,
  useSnackbar,
} from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import SuccessStatus from 'Assets/statuses/success.svg';
import NotificationStatus from 'Assets/statuses/notification.svg';
import LinkButton from 'Components/buttons/LinkButton';
import { extractErrorMessage } from 'Helpers/utils';
import { DeliveryResponseFull } from 'Source/graphql/fragments/DeliveryResponseFull.generated';
import { useSendTestAlertLazyQuery } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { WizardData as CreateWizardData } from '../../CreateDestinationWizard';
import { WizardData as EditWizardData } from '../../EditDestinationWizard';

type DeliveryResponses = Array<DeliveryResponseFull>;
type RowProps = { field: string; value: string | number };

const Row: React.FC<RowProps> = ({ field, value }) => {
  return (
    <React.Fragment>
      <Box as="dt" my="auto">
        {field}
      </Box>
      <Text as="dd" fontWeight="bold">
        {value}
      </Text>
    </React.Fragment>
  );
};

const DestinationTestPanel: React.FC = () => {
  const [testResponses, setTestResponses] = React.useState<DeliveryResponses>([]);
  const {
    data: { destination },
    reset,
    goToPrevStep,
  } = useWizardContext<CreateWizardData & EditWizardData>();

  const { pushSnackbar } = useSnackbar();

  const [sendTestAlert, { loading }] = useSendTestAlertLazyQuery({
    fetchPolicy: 'network-only', // Don't use cache
    variables: {
      input: {
        outputIds: [destination.outputId],
      },
    },
    // Failed deliveries will also trigger onCompleted as we don't return exceptions
    onCompleted: data => setTestResponses(data.sendTestAlert),
    // This will be fired if there was a network issue or other unknown internal exception
    onError: error => {
      trackError({ event: TrackErrorEnum.FailedDestinationTest, src: SrcEnum.Destinations, ctx: destination.outputType}) // prettier-ignore
      pushSnackbar({
        variant: 'error',
        title:
          extractErrorMessage(error) || 'Failed to send a test alert to the given destination(s)',
      });
    },
  });

  const handleTestAlertClick = React.useCallback(() => {
    trackEvent({ event: EventEnum.TestedDestination, src: SrcEnum.Destinations, ctx: destination.outputType }) // prettier-ignore
    sendTestAlert();
  }, [destination]);

  // We are not expecting more than one response since we are sending one ID
  if (testResponses.length && testResponses[0].success === false) {
    trackEvent({ event: EventEnum.TestedDestinationFailure, src: SrcEnum.Destinations, ctx: destination.outputType }) // prettier-ignore
    const { dispatchedAt, message, outputId, statusCode, success } = testResponses[0];
    return (
      <Box maxWidth={700} mx="auto">
        <WizardPanel.Heading
          title="Testing your Destination"
          subtitle="Something went wrong and the destination you have configured did not receive the test alert. Please update your destination settings and try again."
        />
        <Flex direction="column" align="center" spacing={6} my={6}>
          <Card backgroundColor="pink-700" p={6}>
            <Grid
              as="dl"
              wordBreak="break-word"
              templateColumns="max-content 1fr"
              fontSize="medium"
              fontWeight="medium"
              gap={4}
            >
              <Row field="Dispatched at" value={dispatchedAt} />
              <Row field="Message" value={message} />
              <Row field="Output ID" value={outputId} />
              <Row field="Status Code" value={statusCode} />
              <Row field="Success" value={success.toString()} />
            </Grid>
          </Card>
          <Text>
            If you don{"'"}t feel like it right now, you can always change the configuration later
          </Text>
          <LinkButton
            to={urls.settings.destinations.edit(destination.outputId)}
            onClick={goToPrevStep}
          >
            Back to Configuration
          </LinkButton>
          <Link as={RRLink} variant="discreet" to={urls.settings.destinations.list()}>
            Skip Testing
          </Link>
        </Flex>
      </Box>
    );
  }

  if (testResponses.length && testResponses.every(response => response.success === true)) {
    trackEvent({ event: EventEnum.TestedDestinationSuccessfully, src: SrcEnum.Destinations, ctx: destination.outputType }) // prettier-ignore
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
          <Text>Signed, sealed, and delivered. You are good to go!</Text>
          <LinkButton to={urls.settings.destinations.list()}>Finish Setup</LinkButton>
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
