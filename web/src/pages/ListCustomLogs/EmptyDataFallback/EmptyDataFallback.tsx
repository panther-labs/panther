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
