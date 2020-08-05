import React from 'react';
import { Flex, Icon, Text } from 'pouncejs';

interface FieldPolicyCheckProps {
  passing: boolean;
}

const FieldPolicyCheck: React.FC<FieldPolicyCheckProps> = ({ passing, children }) => {
  return (
    <Flex align="center">
      <Icon
        type={passing ? 'check-circle' : 'close-circle'}
        color={passing ? 'green-400' : 'navyblue-100'}
        size="small"
        mr={2}
        aria-label={passing ? 'Check is passing' : 'Check is failing'}
      />
      <Text fontSize="small-medium" color={passing ? undefined : 'navyblue-100'}>
        {children}
      </Text>
    </Flex>
  );
};

export default FieldPolicyCheck;
