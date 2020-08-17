import React from 'react';
import { Box } from 'pouncejs';

const BorderTabDivider: React.FC = () => {
  return (
    <Box
      position="absolute"
      width="100%"
      height={1}
      backgroundColor="navyblue-300"
      zIndex={0}
      left={0}
      marginTop="-1px"
    />
  );
};

export default BorderTabDivider;
