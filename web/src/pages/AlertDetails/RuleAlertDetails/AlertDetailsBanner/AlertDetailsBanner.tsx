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
import { AlertDetailsRuleInfo, AlertTypesEnum } from 'Generated/schema';
import BulletedValue from 'Components/BulletedValue';
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
          <Box as="li">
            <SeverityBadge severity={alert.severity} />
          </Box>
          <Box as="li">
            <UpdateAlertDropdown alert={alert as AlertSummaryFull} />
          </Box>
        </Flex>
      </Flex>
      <Flex as="dl" fontSize="small-medium" pt={5} spacing={8} wrap="wrap">
        <Flex>
          <Box color="navyblue-100" as="dt" pr={2}>
            Alert Type
          </Box>
          <Box
            as="dd"
            fontWeight="bold"
            color={alert.type === AlertTypesEnum.Rule ? 'teal-100' : 'red-500'}
          >
            {alert.type === AlertTypesEnum.Rule ? 'Rule Match' : 'Rule Error'}
          </Box>
        </Flex>
        <Flex>
          <Box color="navyblue-100" as="dt" pr={2}>
            Alert ID
          </Box>
          <Box as="dd" fontWeight="bold">
            {alert.alertId}
          </Box>
        </Flex>
        <Flex>
          <Box color="navyblue-100" as="dt" pr={2}>
            Log Types
          </Box>
          <Flex as="dd" align="center" spacing={6}>
            {(alert.detection as AlertDetailsRuleInfo).logTypes.map(logType => (
              <BulletedValue key={logType} value={logType} />
            ))}
          </Flex>
        </Flex>
      </Flex>
    </Card>
  );
};

export default AlertDetailsBanner;
