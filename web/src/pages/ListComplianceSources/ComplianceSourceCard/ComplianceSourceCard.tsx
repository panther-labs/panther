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
import { Flex, Link } from 'pouncejs';
import GenericItemCard from 'Components/GenericItemCard';
import { ComplianceIntegration } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import urls from 'Source/urls';
import logo from 'Assets/aws-minimal-logo.svg';
import { Link as RRLink } from 'react-router-dom';

import ComplianceSourceCardOptions from './ComplianceSourceCardOptions';
import ComplianceSourceCardHealthBadge from './ComplianceSourceCardHealthBadge';

interface ComplianceSourceCardProps {
  source: ComplianceIntegration;
}

const ComplianceSourceCard: React.FC<ComplianceSourceCardProps> = ({ source }) => {
  return (
    <GenericItemCard>
      <GenericItemCard.Logo src={logo} />
      <ComplianceSourceCardOptions source={source} />
      <GenericItemCard.Body>
        <Link as={RRLink} to={urls.compliance.sources.edit(source.integrationId)} cursor="pointer">
          <GenericItemCard.Heading>{source.integrationLabel}</GenericItemCard.Heading>
        </Link>
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

          <GenericItemCard.LineBreak />
          <GenericItemCard.Value
            label="Date Created"
            value={formatDatetime(source.createdAtTime, true)}
          />
          <Flex ml="auto" mr={0} align="flex-end">
            <ComplianceSourceCardHealthBadge complianceSourceHealth={source.health} />
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default ComplianceSourceCard;
