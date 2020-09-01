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
import { Box, Flex } from 'pouncejs';
import logTypeColorMappings from 'Helpers/logTypeColorMappings';

interface BulletedLogTypeProps {
  logType: string;
}

const BulletedLogType: React.FC<BulletedLogTypeProps> = ({ logType }) => {
  return (
    <Flex spacing={2} align="center">
      <Box
        as="span"
        width={12}
        height={12}
        backgroundColor={logTypeColorMappings[logType]}
        borderRadius="circle"
      />
      <Box as="span" fontSize="small">
        {logType}
      </Box>
    </Flex>
  );
};

export default BulletedLogType;
