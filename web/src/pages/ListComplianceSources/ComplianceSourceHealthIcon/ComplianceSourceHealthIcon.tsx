import React from 'react';
import { Icon, Spinner, Text, Tooltip } from 'pouncejs';
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

  const isHealthy =
    auditRoleStatus.healthy && cweRoleStatus.healthy && remediationRoleStatus.healthy;

  const errorMessage = [
    auditRoleStatus.errorMessage,
    cweRoleStatus.errorMessage,
    remediationRoleStatus.errorMessage,
  ]
    .filter(Boolean)
    .join('. ');

  return isHealthy ? (
    <Tooltip content="All looks fine from our end!">
      <Icon type="check" size="large" color="green300" />
    </Tooltip>
  ) : (
    <Tooltip content={errorMessage}>
      <Icon type="remove" size="large" color="red300" />
    </Tooltip>
  );
};

export default ComplianceSourceHealthIcon;
