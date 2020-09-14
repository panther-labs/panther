import React from 'react';
import { Text, Flex, Icon, AbstractButton } from 'pouncejs';
import { AlertDetails } from 'Pages/AlertDetails';
import last from 'lodash/last';

interface AlertDeliverySectionProps {
  alert: AlertDetails['alert'];
}

const AlertDeliverySection: React.FC<AlertDeliverySectionProps> = ({ alert }) => {
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
      <AbstractButton fontSize="medium" color="teal-400" _hover={{ color: 'teal-300' }}>
        Show History
      </AbstractButton>
    </Flex>
  );
};

export default AlertDeliverySection;
