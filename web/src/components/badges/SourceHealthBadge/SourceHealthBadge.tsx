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
import { Badge, Flex, Icon, Tooltip, Text, Box } from 'pouncejs';
import { IntegrationItemHealthStatus } from 'Generated/schema';
import { slugify } from 'Helpers/utils';

interface SourceHealthBadgeProps {
  healthMetrics: IntegrationItemHealthStatus[];
}

const SourceHealthBadge: React.FC<SourceHealthBadgeProps> = ({ healthMetrics }) => {
  const isHealthy = healthMetrics.every(healthMetric => Boolean(healthMetric.healthy));

  const tooltipContent = (
    <Flex direction="column" spacing={1}>
      {healthMetrics.map(healthMetric => {
        const id = slugify(healthMetric.message);
        return (
          <Flex spacing={2} key={id}>
            <Icon
              mt="-2px" // we need that due to some alignment needs with `rawErrorMessage`
              aria-labelledby={id}
              size="medium"
              type={healthMetric.healthy ? 'check' : 'remove'}
              color={healthMetric.healthy ? 'green-400' : 'red-300'}
              aria-label={healthMetric.healthy ? 'Passing' : 'Failing'}
            />
            <Box>
              <Text id={id} aria-describedby={`${id}-description`}>
                {healthMetric.message}
              </Text>
              {!!healthMetric.rawErrorMessage && (
                <Text
                  my={1}
                  fontSize="x-small"
                  color="red-200"
                  id={`${id}-description`}
                  maxWidth="fit-content"
                >
                  {healthMetric.rawErrorMessage}
                </Text>
              )}
            </Box>
          </Flex>
        );
      })}
    </Flex>
  );

  const icon = isHealthy ? (
    <Badge color="green-400">HEALTHY</Badge>
  ) : (
    <Badge color="red-300">UNHEALTHY</Badge>
  );

  return <Tooltip content={tooltipContent}>{icon}</Tooltip>;
};

export default React.memo(SourceHealthBadge);
