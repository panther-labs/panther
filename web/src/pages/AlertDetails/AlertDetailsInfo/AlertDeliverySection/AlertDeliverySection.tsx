import React from 'react';
import { Text, Flex, Icon, AbstractButton, Box, Collapse } from 'pouncejs';
import { AlertDetails, ListDestinations } from 'Pages/AlertDetails';
import AlertDeliveryTable from 'Pages/AlertDetails/AlertDetailsInfo/AlertDeliverySection/AlertDeliveryTable';

interface AlertDeliverySectionProps {
  alertDeliveries: AlertDetails['alert']['deliveryResponses'];
  configuredAlertDestinations: ListDestinations['destinations'];
}

const AlertDeliverySection: React.FC<AlertDeliverySectionProps> = ({
  alertDeliveries,
  configuredAlertDestinations,
}) => {
  const [isHistoryVisible, setHistoryVisibility] = React.useState(false);

  // FIXME: `configuredAlertDestinations` should be part of Alert & coming directly from GraphQL
  //  Someday...
  const enhancedAlertDeliveries = React.useMemo(() => {
    return alertDeliveries
      .map(dr => ({
        ...dr,
        ...configuredAlertDestinations.find(d => d.outputId === dr.outputId),
      }))
      .reverse();
  }, [alertDeliveries, configuredAlertDestinations]);

  if (!alertDeliveries.length) {
    return (
      <Flex align="warning" spacing={4}>
        <Icon type="info" size="small" color="blue-400" />
        <Text fontWeight="medium">Delivery information could not be retrieved</Text>
      </Flex>
    );
  }

  const isMostRecentDeliverySuccessful = alertDeliveries[0].success;
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
          <AlertDeliveryTable alertDeliveries={enhancedAlertDeliveries} />
        </Box>
      </Collapse>
    </Box>
  );
};

export default AlertDeliverySection;
