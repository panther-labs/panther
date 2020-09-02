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
import { Badge, Box, Tooltip } from 'pouncejs';
import { ComplianceIntegration } from 'Generated/schema';

interface ComplianceSourceCardHealthBadgeProps {
  complianceSourceHealth: ComplianceIntegration['health'];
}

const ComplianceSourceCardHealthBadge: React.FC<ComplianceSourceCardHealthBadgeProps> = ({
  complianceSourceHealth,
}) => {
  const { auditRoleStatus, cweRoleStatus, remediationRoleStatus } = complianceSourceHealth;

  const isHealthy =
    auditRoleStatus.healthy && cweRoleStatus.healthy && remediationRoleStatus.healthy;

  const errorMessage = [
    auditRoleStatus?.rawErrorMessage,
    cweRoleStatus?.rawErrorMessage,
    remediationRoleStatus?.rawErrorMessage,
  ]
    .filter(Boolean)
    .join('. ');

  const tooltipMessage = isHealthy ? 'Everything looks fine from our end!' : errorMessage;
  const icon = isHealthy ? (
    <Badge color="green-400">HEALTHY</Badge>
  ) : (
    <Badge color="red-300">UNHEALTHY</Badge>
  );

  return (
    <Box>
      <Tooltip content={tooltipMessage}>{icon}</Tooltip>
    </Box>
  );
};

export default ComplianceSourceCardHealthBadge;
