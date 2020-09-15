import React from 'react';
import { Text, Flex, Icon, AbstractButton, Box, Collapse } from 'pouncejs';
import { AlertDetails } from 'Pages/AlertDetails';
import last from 'lodash/last';
import AlertDeliveryTable from 'Pages/AlertDetails/AlertDetailsInfo/AlertDeliverySection/AlertDeliveryTable';

interface AlertDeliverySectionProps {
  alert: AlertDetails['alert'];
}

const AlertDeliverySection: React.FC<AlertDeliverySectionProps> = ({ alert }) => {
  const [isHistoryVisible, setHistoryVisibility] = React.useState(false);

  const { deliveryResponses } = alert;
  if (!deliveryResponses.length) {
    return (
      <Flex align="warning" spacing={4}>
        <Icon type="info" size="small" color="blue-400" />
        <Text fontWeight="medium">Delivery information could not be retrieved</Text>
      </Flex>
    );
  }

  const isLastDeliverySuccessful = last(deliveryResponses).success;
  return (
    <Box>
      <Flex justify="space-between">
        {isLastDeliverySuccessful ? (
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
          <AlertDeliveryTable alertDeliveries={deliveryResponses} />
        </Box>
      </Collapse>
    </Box>
  );
};

export default AlertDeliverySection;
