import React from 'react';
import { Box, Icon, Label, Tooltip } from 'pouncejs';
import { ComplianceIntegration } from 'Generated/schema';

interface ComplianceSourceHealthIconProps {
  complianceSourceHealth: ComplianceIntegration['health'];
}

const ComplianceSourceHealthIcon: React.FC<ComplianceSourceHealthIconProps> = ({
  complianceSourceHealth,
}) => {
  const { auditRoleStatus, cweRoleStatus, remediationRoleStatus } = complianceSourceHealth;

  // Some status return `null` when they shouldn't be checked. That doesn't mean the source is
  // unhealthy. That's why we check explicitly for a "false" value
  const isHealthy =
    auditRoleStatus.healthy !== false &&
    cweRoleStatus.healthy !== false &&
    remediationRoleStatus.healthy !== false;

  const errorMessage = [
    auditRoleStatus.errorMessage,
    cweRoleStatus.errorMessage,
    remediationRoleStatus.errorMessage,
  ]
    .filter(Boolean)
    .join('. ');

  const tooltipMessage = isHealthy ? 'Everything looks fine from our end!' : errorMessage;
  const icon = isHealthy ? (
    <Icon type="check" size="large" color="green300" />
  ) : (
    <Icon type="close" size="large" color="red300" />
  );

  return (
    <Box>
      <Tooltip content={<Label size="medium">{tooltipMessage}</Label>} positioning="down">
        {icon}
      </Tooltip>
    </Box>
  );
};

export default ComplianceSourceHealthIcon;
