/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import WarningImg from 'Assets/illustrations/warning.svg';
import { Box, Flex, Heading, Text } from 'pouncejs';

const LogAnalysisOverview: React.FC = () => {
  return (
    <Flex
      height="100%"
      width="100%"
      justifyContent="center"
      alignItems="center"
      flexDirection="column"
    >
      <Box m={10}>
        <img alt="Construction works" src={WarningImg} width="auto" height={400} />
      </Box>
      <Heading size="medium" color="grey400" mb={6}>
        Log analysis overview is not available
      </Heading>
      <Text size="large" color="grey200" textAlign="center" mb={10}>
        We are currently developing this page and will release it in the near future
      </Text>
    </Flex>
  );
};

export default LogAnalysisOverview;
