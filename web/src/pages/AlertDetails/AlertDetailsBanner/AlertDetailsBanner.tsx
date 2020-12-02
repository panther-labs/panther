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

import { Box, Flex, Heading, Card } from 'pouncejs';
import React from 'react';
import SeverityBadge from 'Components/badges/SeverityBadge';
import { AlertTypesEnum } from 'Generated/schema';
import BulletedLogType from 'Components/BulletedLogType';
import UpdateAlertDropdown from 'Components/dropdowns/UpdateAlertDropdown';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';
import { AlertDetails } from 'Pages/AlertDetails';

interface AlertDetailsBannerProps {
  alert: AlertDetails['alert'];
}

const AlertDetailsBanner: React.FC<AlertDetailsBannerProps> = ({ alert }) => {
  return (
    <Card
      as="article"
      p={6}
      overflow="hidden"
      borderLeft="4px solid"
      borderColor={alert.type === AlertTypesEnum.Rule ? 'teal-400' : 'red-600'}
    >
      <Flex as="header" align="center">
        <Heading fontWeight="bold" wordBreak="break-word" flexShrink={1} mr={100}>
          {alert.title || alert.alertId}
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
      <Flex fontSize="small-medium" pt={5} spacing={8}>
        <Flex>
          <Box color="navyblue-100" aria-describedby="rule-type" as="dd" pr={2}>
            Alert Type
          </Box>
          <Box
            id="rule-type"
            as="dl"
            fontWeight="bold"
            color={alert.type === AlertTypesEnum.Rule ? 'teal-100' : 'red-500'}
          >
            {alert.type === AlertTypesEnum.Rule ? 'Rule Match' : 'Rule Error'}
          </Box>
        </Flex>
        <Flex>
          <Box color="navyblue-100" aria-describedby="alert-id" as="dd" pr={2}>
            Alert ID
          </Box>
          <Box id="alert-id" as="dl" fontWeight="bold">
            {alert.alertId}
          </Box>
        </Flex>
        <Flex>
          <Box color="navyblue-100" aria-describedby="alert-log-types" as="dd" pr={2}>
            Log Types
          </Box>
          <Box id="alert-log-types" as="dl">
            <Flex align="center" spacing={6}>
              {alert.logTypes.map(logType => (
                <BulletedLogType key={logType} logType={logType} />
              ))}
            </Flex>
          </Box>
        </Flex>
      </Flex>
    </Card>
  );
};

export default AlertDetailsBanner;
