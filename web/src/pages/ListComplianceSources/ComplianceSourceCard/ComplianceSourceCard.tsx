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
import { Flex, Link, Text, Tooltip } from 'pouncejs';
import GenericItemCard from 'Components/GenericItemCard';
import { ComplianceIntegration } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import urls from 'Source/urls';
import logo from 'Assets/aws-minimal-logo.svg';
import { Link as RRLink } from 'react-router-dom';
import SourceHealthBadge from 'Components/badges/SourceHealthBadge';
import { PANTHER_USER_ID } from 'Source/constants';
import ComplianceSourceCardOptions from './ComplianceSourceCardOptions';

interface ComplianceSourceCardProps {
  source: ComplianceIntegration;
}

const ComplianceSourceCard: React.FC<ComplianceSourceCardProps> = ({ source }) => {
  const isCreatedByPanther = source.createdBy === PANTHER_USER_ID;

  const healthMetrics = React.useMemo(
    () => [
      source.health.auditRoleStatus,
      source.health.cweRoleStatus,
      source.health.remediationRoleStatus,
    ],
    [source.health]
  );

  return (
    <GenericItemCard>
      <GenericItemCard.Logo src={logo} />
      {!isCreatedByPanther && (
        <GenericItemCard.Options>
          <ComplianceSourceCardOptions source={source} />
        </GenericItemCard.Options>
      )}
      <GenericItemCard.Body>
        {!isCreatedByPanther ? (
          <GenericItemCard.Heading>
            <Link as={RRLink} to={urls.compliance.sources.edit(source.integrationId)}>
              {source.integrationLabel}
            </Link>
          </GenericItemCard.Heading>
        ) : (
          <GenericItemCard.Heading>
            <Tooltip content="This is a compliance source we created for you.">
              <Text color="teal-300" as="span">
                {source.integrationLabel}
              </Text>
            </Tooltip>
          </GenericItemCard.Heading>
        )}
        <GenericItemCard.ValuesGroup>
          <GenericItemCard.Value label="AWS Account ID" value={source.awsAccountId} />
          <GenericItemCard.Value
            label="Real-Time Updates"
            value={source.cweEnabled ? 'Enabled' : 'Disabled'}
          />
          <GenericItemCard.Value
            label="Auto-Remediations"
            value={source.remediationEnabled ? 'Enabled' : 'Disabled'}
          />
          <GenericItemCard.Value label="AWS Stack Name" value={source.stackName} />
          <GenericItemCard.LineBreak />
          <GenericItemCard.Value
            label="Date Created"
            value={formatDatetime(source.createdAtTime, true)}
          />
          <Flex ml="auto" mr={0} align="flex-end">
            <SourceHealthBadge healthMetrics={healthMetrics} />
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default ComplianceSourceCard;
