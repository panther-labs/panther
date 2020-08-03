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
import { Box, Icon, Tooltip } from 'pouncejs';
import { LogIntegration, S3LogIntegration, SqsLogSourceIntegration } from 'Generated/schema';

interface LogSourceHealthIconProps {
  logSourceHealth: LogIntegration['health'];
}

const LogSourceHealthIcon: React.FC<LogSourceHealthIconProps> = ({ logSourceHealth }) => {
  let isHealthy: boolean;
  let errorMsg: string;
  let sourceHealth: LogIntegration['health'];

  switch (logSourceHealth.__typename) {
    case 'SqsLogIntegrationHealth':
      sourceHealth = logSourceHealth as SqsLogSourceIntegration['health'];
      isHealthy = sourceHealth.sqsStatus?.healthy !== false;
      errorMsg = sourceHealth.sqsStatus?.errorMessage;
      break;
    case 'S3LogIntegrationHealth': {
      sourceHealth = logSourceHealth as S3LogIntegration['health'];
      const { processingRoleStatus, s3BucketStatus, kmsKeyStatus } = sourceHealth;
      // Some status return `null` when they shouldn't be checked. That doesn't mean the source is
      // unhealthy. That's why we check explicitly for a "false" value
      isHealthy =
        processingRoleStatus?.healthy !== false &&
        s3BucketStatus?.healthy !== false &&
        kmsKeyStatus?.healthy !== false;
      errorMsg = [
        processingRoleStatus?.errorMessage,
        s3BucketStatus?.errorMessage,
        kmsKeyStatus?.errorMessage,
      ]
        .filter(Boolean)
        .join('. ');
      break;
    }
    default:
      isHealthy = false;
      errorMsg = 'Couldn\t determine source health';
  }
  const tooltipMessage = isHealthy ? 'Everything looks fine from our end!' : errorMsg;
  const icon = isHealthy ? (
    <Icon type="check" size="small" color="green-400" />
  ) : (
    <Icon type="close" size="small" color="red-300" />
  );

  return (
    <Box>
      <Tooltip content={tooltipMessage}>{icon}</Tooltip>
    </Box>
  );
};

export default LogSourceHealthIcon;
