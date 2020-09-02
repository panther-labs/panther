import React from 'react';
import { Badge, Box, Flex, Icon, Tooltip, Text } from 'pouncejs';
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
          <Flex align="center" spacing={2} key={id}>
            <Icon
              aria-labelledby={id}
              size="small"
              type={healthMetric.healthy ? 'check' : 'remove'}
              color={healthMetric.healthy ? 'green-400' : 'red-300'}
            />
            <Text title={healthMetric.rawErrorMessage || undefined} id={id}>
              {healthMetric.message}
            </Text>
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

  return (
    <Box>
      <Tooltip content={tooltipContent}>{icon}</Tooltip>
    </Box>
  );
};

export default React.memo(SourceHealthBadge);
