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
import { Badge, BadgeProps, Box, Tooltip } from 'pouncejs';
import { ComplianceStatusEnum } from 'Generated/schema';

export const STATUS_COLOR_MAP: { [key in StatusBadgeProps['status']]: BadgeProps['color'] } = {
  [ComplianceStatusEnum.Pass]: 'green-500' as const,
  [ComplianceStatusEnum.Fail]: 'red-200' as const,
  [ComplianceStatusEnum.Error]: 'orange-400' as const,
  ENABLED: 'cyan-400' as const,
};

interface StatusBadgeProps {
  status: ComplianceStatusEnum | 'ENABLED';
  disabled?: boolean;
  errorMessage?: string;
  disabledLabel?: string;
}

const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  disabled,
  errorMessage = "An exception has been raised during a scheduled run. You'll find more information in the related details page",
  disabledLabel = 'DISABLED',
}) => {
  if (disabled) {
    return (
      <Box opacity={0.5}>
        <Badge color="navyblue-300">{disabledLabel}</Badge>
      </Box>
    );
  }

  if (status === ComplianceStatusEnum.Error) {
    return (
      <Tooltip content={errorMessage}>
        <Badge color={STATUS_COLOR_MAP[status]}>{status}</Badge>
      </Tooltip>
    );
  }
  return <Badge color={STATUS_COLOR_MAP[status]}>{status}</Badge>;
};

export default StatusBadge;
