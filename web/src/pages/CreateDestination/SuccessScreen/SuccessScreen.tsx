import React from 'react';
import { ForwardedStepContextValue } from 'Pages/CreateDestination/ConfigureDestinationScreen';
import { useWizardContext, WizardPanelWrapper } from 'Components/Wizard';
import { Button, Text, Tooltip, Link } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';

type TestStatus = 'PASSED' | 'FAILED' | null;

const SuccessScreen: React.FC = () => {
  const [testStatus, sendTestStatus] = React.useState<TestStatus>(null);
  const {
    stepContext: { destination },
  } = useWizardContext<ForwardedStepContextValue>();

  const handleTestAlertClick = React.useCallback(() => {
    // FIXME: add logic for alert testing and then update the `sendTestStatus` call below
    sendTestStatus('PASSED');
  }, []);

  if (testStatus === 'FAILED') {
    return (
      <React.Fragment>
        <WizardPanelWrapper.Heading
          title="Testing your Destination"
          subtitle="Something went wrong and the destination you have configured did not receive the test alert. Please try setting up the destination and try again."
        />

        <Text mb={5}>
          If you want, you can always configure your destination again later by the destinations
          page
        </Text>
        <Link as={RRLink} mb={6} to={urls.settings.destinations.edit(destination.outputId)}>
          <Button as="div">Back to Configuration</Button>
        </Link>
        <Link as={RRLink} variant="discreet" to={urls.settings.destinations.list()}>
          Skip Testing
        </Link>
      </React.Fragment>
    );
  }

  if (testStatus === 'PASSED') {
    return (
      <React.Fragment>
        <WizardPanelWrapper.Heading
          title="Testing your Destination"
          subtitle="Everything worked as planned and your destination received the triggered alert. You can always send a test alert from the destinations page."
        />

        <Text mb={5}>You can now add another destination or finish this setup</Text>
        <Link as={RRLink} mb={6} to={urls.settings.destinations.list()}>
          <Button as="div">Finish Setup</Button>
        </Link>
        <Link as={RRLink} variant="discreet" to={urls.settings.destinations.create()}>
          Add Another
        </Link>
      </React.Fragment>
    );
  }

  return (
    <React.Fragment>
      <WizardPanelWrapper.Heading
        title="Everything looks good!"
        subtitle="Your destination was successfully added and you will receive alerts based on your configuration.You can always edit or delete this destination from the destinations page"
      />

      <Text mb={5}>Do you want to try it out by sending a test Alert?</Text>
      <Tooltip content="The ability to test your destination is coming really soon!">
        <Button disabled onClick={handleTestAlertClick}>
          Send Test Alert
        </Button>
      </Tooltip>
    </React.Fragment>
  );
};

export default SuccessScreen;
