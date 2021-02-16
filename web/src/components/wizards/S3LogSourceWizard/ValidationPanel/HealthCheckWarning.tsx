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
import { Box, Flex, Text, Img } from 'pouncejs';
import WarningIcon from 'Assets/icons/warning.svg';

interface WarningProps {
  title: string;
  description?: string;
}
const HealthCheckWarning: React.FC<WarningProps> = ({ title, description }) => {
  return (
    <Flex spacing={4} backgroundColor="navyblue-500" p={4}>
      <Img src={WarningIcon} alt="Warning" nativeWidth={24} nativeHeight={24} />
      <Box>
        <Text fontSize="medium" pb={2}>
          {title}
        </Text>
        <Text fontSize="small" color="gray-300">
          {description}
        </Text>
      </Box>
    </Flex>
  );
};

export default React.memo(HealthCheckWarning);
