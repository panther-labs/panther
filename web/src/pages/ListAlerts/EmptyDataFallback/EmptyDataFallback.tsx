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
import SecurityCheckImg from 'Assets/illustrations/security-check.svg';
import { Box, Flex, Heading, Text } from 'pouncejs';

const ListAlertsPageEmptyDataFallback: React.FC = () => {
  return (
    <Flex height="100%" width="100%" justify="center" align="center" direction="column">
      <Box m={10}>
        <img
          alt="Shield with checkmark illustration"
          src={SecurityCheckImg}
          width="auto"
          height={350}
        />
      </Box>
      <Heading size="medium" color="grey400" mb={6}>
        It{"'"}s quiet in here
      </Heading>
      <Text size="large" color="grey200" textAlign="center" mb={10}>
        Any suspicious rule-based activity we detect will be listed here
      </Text>
    </Flex>
  );
};

export default ListAlertsPageEmptyDataFallback;
