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

import { Box, Flex, Heading, Tooltip, Icon, Card } from 'pouncejs';
import React from 'react';
import SeverityBadge from 'Components/badges/SeverityBadge';
import UpdateAlertDropdown from 'Components/dropdowns/UpdateAlertDropdown';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { AlertDetails } from 'Pages/AlertDetails';

interface AlertDetailsBannerProps {
  alert: AlertDetails['alert'];
}

const AlertDetailsBanner: React.FC<AlertDetailsBannerProps> = ({ alert }) => {
  return (
    <Card as="article" p={6}>
      <Flex as="header" align="top">
        <Heading fontWeight="bold" wordBreak="break-word" flexShrink={1} mr={100}>
          {alert.title || alert.alertId}
          <Tooltip
            content={
              <Flex spacing={3}>
                <Flex direction="column" spacing={2}>
                  <Box id="alert-id-label">Alert ID</Box>
                  <Box id="log-types-label">Log Types</Box>
                </Flex>
                <Flex direction="column" spacing={2} fontWeight="bold">
                  <Box aria-labelledby="alert-id-label">{alert.alertId}</Box>
                  <Box aria-labelledby="log-types-label">
                    {alert.logTypes.map(logType => <Box key={logType}>{logType}</Box>) ?? 'N/A'}
                  </Box>
                </Flex>
              </Flex>
            }
          >
            <Icon type="info" size="small" verticalAlign="unset" ml={2} />
          </Tooltip>
        </Heading>
        <Flex spacing={2} as="ul" flexShrink={0} ml="auto">
          <Box as="li" aria-describedby="alert-severity-description">
            <SeverityBadge severity={alert.severity} />
          </Box>
          <Box as="li" aria-describedby="alert-status-description">
            <UpdateAlertDropdown alert={alert as AlertSummaryFull} />
          </Box>
        </Flex>
      </Flex>
    </Card>
  );
};

export default AlertDetailsBanner;
