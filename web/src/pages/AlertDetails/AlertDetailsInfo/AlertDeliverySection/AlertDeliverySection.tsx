import React from 'react';
import { Text, Flex, Icon, AbstractButton, Box, Collapse, useSnackbar } from 'pouncejs';
import { AlertDetails, ListDestinations } from 'Pages/AlertDetails';
import AlertDeliveryTable from './AlertDeliveryTable';
import { useRetryAlertDelivery } from './graphql/retryAlertDelivery.generated';

interface AlertDeliverySectionProps {
  alert: AlertDetails['alert'];
  alertDestinations: ListDestinations['destinations'];
}

const AlertDeliverySection: React.FC<AlertDeliverySectionProps> = ({
  alert,
  alertDestinations,
}) => {
  const [isHistoryVisible, setHistoryVisibility] = React.useState(false);

  const { pushSnackbar } = useSnackbar();
  const [retryAlertDelivery] = useRetryAlertDelivery({
    update: (cache, { data }) => {
      const dataId = cache.identify({
        __typename: 'AlertDetails',
        alertId: data.deliverAlert.alertId,
      });

      cache.modify(dataId, {
        deliveryResponses: () => data.deliverAlert.deliveryResponses,
      });
    },
    onError: () => pushSnackbar({ variant: 'error', title: 'Failed to deliver alert' }),
    onCompleted: () => pushSnackbar({ variant: 'success', title: 'Successfully delivered alert' }),
  });

  const onAlertDeliveryRetry = React.useCallback(
    (outputId: string) => {
      retryAlertDelivery({
        variables: {
          input: {
            alertId: alert.alertId,
            outputIds: [outputId],
          },
        },
      });
    },
    [retryAlertDelivery, alert]
  );

  // FIXME: `alertDestinations` should be part of Alert & coming directly from GraphQL
  //  Someday...
  const { deliveryResponses } = alert;
  const enhancedAlertDeliveries = React.useMemo(() => {
    return deliveryResponses
      .map(dr => ({
        ...dr,
        ...alertDestinations.find(d => d.outputId === dr.outputId),
      }))
      .reverse();
  }, [deliveryResponses, alertDestinations]);

  if (!deliveryResponses.length) {
    return (
      <Flex align="warning" spacing={4}>
        <Icon type="info" size="small" color="blue-400" />
        <Text fontWeight="medium">Delivery information could not be retrieved</Text>
      </Flex>
    );
  }

  const isMostRecentDeliverySuccessful = deliveryResponses[0].success;
  return (
    <Box>
      <Flex justify="space-between">
        {isMostRecentDeliverySuccessful ? (
          <Flex align="center" spacing={4}>
            <Icon type="check-circle" size="small" color="green-400" />
            <Text fontWeight="medium">Alert was delivered successfully</Text>
          </Flex>
        ) : (
          <Flex align="center" spacing={4}>
            <Icon type="alert-circle" size="small" color="red-300" />
            <Text fontWeight="medium" color="red-300">
              Alert delivery failed
            </Text>
          </Flex>
        )}
        <AbstractButton
          fontSize="medium"
          color="teal-400"
          _hover={{ color: 'teal-300' }}
          onClick={() => setHistoryVisibility(!isHistoryVisible)}
        >
          {isHistoryVisible ? 'Hide History' : 'Show History'}
        </AbstractButton>
      </Flex>
      <Collapse open={isHistoryVisible}>
        <Box backgroundColor="navyblue-400" mt={6}>
          <AlertDeliveryTable
            alertDeliveries={enhancedAlertDeliveries}
            onAlertDeliveryRetry={onAlertDeliveryRetry}
          />
        </Box>
      </Collapse>
    </Box>
  );
};

export default AlertDeliverySection;
