/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Box, Flex, Heading, Text } from 'pouncejs';
import EmptyDataImg from 'Assets/illustrations/empty-box.svg';

const ListCustomLogsPageEmptyDataFallback: React.FC = () => {
  return (
    <Flex height="100%" width="100%" justify="center" align="center" direction="column">
      <Box m={10}>
        <img alt="Empty data illustration" src={EmptyDataImg} width="auto" height={350} />
      </Box>
      <Heading mb={6}>You don{"'"}t have any custom schemas</Heading>
      <Text color="gray-300" textAlign="center" mb={8}>
        A custom schema allows Panther to parse arbitrary logs that are tailored to your business
      </Text>
    </Flex>
  );
};

export default ListCustomLogsPageEmptyDataFallback;
