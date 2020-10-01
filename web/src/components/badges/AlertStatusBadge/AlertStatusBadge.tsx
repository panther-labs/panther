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
import { Badge, BadgeProps, Box, Flex, Tooltip } from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';

const STATUS_COLOR_MAP: {
  [key in StatusBadgeProps['status']]: BadgeProps['color'];
} = {
  [AlertStatusesEnum.Open]: 'magenta-400' as const,
  [AlertStatusesEnum.Triaged]: 'purple-500' as const,
  [AlertStatusesEnum.Closed]: 'navyblue-300' as const,
  [AlertStatusesEnum.Resolved]: 'indigo-700' as const,
};

interface StatusBadgeProps {
  status: AlertStatusesEnum;
  lastUpdatedBy?: string;
  lastUpdatedByTime?: string;
}

const AlertStatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  lastUpdatedBy,
  lastUpdatedByTime,
}) => {
  const statusBadge = React.useMemo(
    () => (
      <Flex width={'85px'}>
        <Badge color={STATUS_COLOR_MAP[status]}>
          {status === AlertStatusesEnum.Closed ? 'INVALID' : status}
        </Badge>
      </Flex>
    ),
    [status]
  );

  return lastUpdatedBy ? (
    <Tooltip
      content={
        <Flex spacing={1}>
          <Flex direction="column" spacing={1}>
            <Box id="user-name-label">By</Box>
            <Box id="updated-by-timestamp-label">At</Box>
          </Flex>
          <Flex direction="column" spacing={1} fontWeight="bold">
            <Box aria-labelledby="user-name-label">{lastUpdatedBy}</Box>
            <Box aria-labelledby="updated-by-timestamp-label">{lastUpdatedByTime}</Box>
          </Flex>
        </Flex>
      }
    >
      {statusBadge}
    </Tooltip>
  ) : (
    statusBadge
  );
};

export default AlertStatusBadge;
