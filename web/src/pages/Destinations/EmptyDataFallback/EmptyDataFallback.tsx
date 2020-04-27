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
import DestinationImg from 'Assets/illustrations/destination.svg';
import { Box, Flex, Heading, Text } from 'pouncejs';
import DestinationCreateButton from '../CreateButton';

const DestinationsPageEmptyDataFallback: React.FC = () => {
  return (
    <Flex height="100%" width="100%" justify="center" align="center" direction="column">
      <Box m={10}>
        <img alt="Mobile & Envelope illustration" src={DestinationImg} width="auto" height={350} />
      </Box>
      <Heading size="medium" color="grey400" mb={6}>
        Help us reach you
      </Heading>
      <Text size="large" color="grey200" textAlign="center" mb={10}>
        You don{"'"}t seem to have any destinations setup yet. <br />
        Adding destinations will help you get notified when irregularities occur.
      </Text>
      <DestinationCreateButton />
    </Flex>
  );
};

export default DestinationsPageEmptyDataFallback;
