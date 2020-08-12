import React from 'react';
import { useWizardContext, WizardPanelWrapper } from 'Components/Wizard';
import { Button, Text, Tooltip, Link, Img, Flex, Box, AbstractButton } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import SuccessStatus from 'Assets/statuses/success.svg';
import FailureStatus from 'Assets/statuses/failure.svg';
import NotificationStatus from 'Assets/statuses/notification.svg';
import { WizardData } from '../CreateDestination';

type TestStatus = 'PASSED' | 'FAILED' | null;

const SuccessScreen: React.FC = () => {
  const [testStatus, sendTestStatus] = React.useState<TestStatus>('PASSED');
  const {
    data: { destination },
    reset,
  } = useWizardContext<WizardData>();

  const handleTestAlertClick = React.useCallback(() => {
    // FIXME: add logic for alert testing and then update the `sendTestStatus` call below
    sendTestStatus('PASSED');
  }, []);

  if (testStatus === 'FAILED') {
    return (
      <React.Fragment>
        <WizardPanelWrapper.Heading
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
            <Button as="div">Back to Configuration</Button>
          </Link>
          <Link as={RRLink} variant="discreet" to={urls.settings.destinations.list()}>
            Skip Testing
          </Link>
        </Flex>
      </React.Fragment>
    );
  }

  if (testStatus === 'PASSED') {
    return (
      <React.Fragment>
        <WizardPanelWrapper.Heading
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
      </React.Fragment>
    );
  }

  return (
    <React.Fragment>
      <WizardPanelWrapper.Heading
        title="Everything looks good!"
        subtitle="Your destination was successfully added and you will receive alerts based on your configuration.You can always edit or delete this destination from the destinations page"
      />
      <Flex direction="column" align="center" spacing={6} my={6}>
        <Img nativeWidth={120} nativeHeight={120} alt="Success" src={SuccessStatus} />
        <Text mb={5}>Do you want to try it out by sending a test Alert?</Text>
        <Tooltip content="The ability to test your destination is coming really soon!">
          <Box>
            <Button disabled onClick={handleTestAlertClick}>
              Send Test Alert
            </Button>
          </Box>
        </Tooltip>
        <Link as={RRLink} variant="discreet" to={urls.settings.destinations.list()}>
          Finish Setup
        </Link>
      </Flex>
    </React.Fragment>
  );
};

export default SuccessScreen;
