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
import { Box, Icon, Label, Tooltip } from 'pouncejs';
import { LogIntegration } from 'Generated/schema';

interface LogSourceHealthIconProps {
  logSourceHealth: LogIntegration['health'];
}

const LogSourceHealthIcon: React.FC<LogSourceHealthIconProps> = ({ logSourceHealth }) => {
  const { processingRoleStatus, s3BucketStatus, kmsKeyStatus } = logSourceHealth;

  // Some status return `null` when they shouldn't be checked. That doesn't mean the source is
  // unhealthy. That's why we check explicitly for a "false" value
  const isHealthy =
    processingRoleStatus.healthy !== false &&
    s3BucketStatus.healthy !== false &&
    kmsKeyStatus.healthy !== false;

  const errorMessage = [
    processingRoleStatus.errorMessage,
    s3BucketStatus.errorMessage,
    kmsKeyStatus.errorMessage,
  ]
    .filter(Boolean)
    .join('. ');

  const tooltipMessage = isHealthy ? 'Everything looks fine from our end!' : errorMessage;
  const icon = isHealthy ? (
    <Icon type="check" size="small" color="green300" />
  ) : (
    <Icon type="close" size="small" color="red300" />
  );

  return (
    <Box>
      <Tooltip content={<Label size="medium">{tooltipMessage}</Label>} positioning="down">
        {icon}
      </Tooltip>
    </Box>
  );
};

export default LogSourceHealthIcon;
