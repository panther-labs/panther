import React from 'react';
import { Box, Icon, Label, Spinner, Text, Tooltip } from 'pouncejs';
import { ComplianceIntegrationDetails } from 'Source/graphql/fragments/ComplianceIntegrationDetails.generated';
import { useGetComplianceSourceHealth } from './graphql/getComplianceSourceHealth.generated';

interface ComplianceSourceHealthIconProps {
  source: ComplianceIntegrationDetails;
}

const ComplianceSourceHealthIcon: React.FC<ComplianceSourceHealthIconProps> = ({ source }) => {
  const { data, loading, error } = useGetComplianceSourceHealth({
    variables: {
      input: {
        awsAccountId: source.awsAccountId,
        enableCWESetup: source.cweEnabled ?? false,
        enableRemediation: source.remediationEnabled ?? false,
      },
    },
  });

  if (loading) {
    return <Spinner size="small" />;
  }

  if (error) {
    return (
      <Text size="large" color="grey200">
        N/A
      </Text>
    );
  }

  const {
    auditRoleStatus,
    cweRoleStatus,
    remediationRoleStatus,
  } = data.getComplianceIntegrationHealth;

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
