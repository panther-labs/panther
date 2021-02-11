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
import GenericItemCard from 'Components/GenericItemCard';
import { Box, Flex, Link, SimpleGrid, Text } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';
import BulletedValueList from 'Components/BulletedValueList';
import urls from 'Source/urls';
import { PolicySummary } from 'Source/graphql/fragments/PolicySummary.generated';
import { ComplianceStatusEnum } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import { SelectCheckbox } from 'Components/utils/SelectContext';
import useDetectionDestinations from 'Hooks/useDetectionDestinations';
import RelatedDestinations from 'Components/RelatedDestinations';
import PolicyCardOptions from './PolicyCardOptions';

interface PolicyCardProps {
  policy: PolicySummary;
  selectionEnabled?: boolean;
  isSelected?: boolean;
}

const PolicyCard: React.FC<PolicyCardProps> = ({
  policy,
  selectionEnabled = false,
  isSelected = false,
}) => {
  const {
    detectionDestinations,
    loading: loadingDetectionDestinations,
  } = useDetectionDestinations({ detection: policy });
  return (
    <GenericItemCard isHighlighted={isSelected}>
      {selectionEnabled && (
        <Box transform="translate3d(-12px,-12px,0)">
          <SelectCheckbox selectionItem={policy} />
        </Box>
      )}
      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            <Link
              as={RRLink}
              aria-label="Link to Policy"
              to={urls.compliance.policies.details(policy.id)}
            >
              {policy.displayName || policy.id}
            </Link>
          </GenericItemCard.Heading>
          <GenericItemCard.Date date={formatDatetime(policy.lastModified)} />
          <PolicyCardOptions policy={policy} />
        </GenericItemCard.Header>
        <Text fontSize="small" as="span" color="indigo-300">
          Policy
        </Text>
        <SimpleGrid gap={2} columns={2}>
          <GenericItemCard.ValuesGroup>
            <GenericItemCard.Value
              label="Resource Types"
              value={<BulletedValueList values={policy.resourceTypes} limit={2} />}
            />
            <GenericItemCard.Value
              label="Destinations"
              value={
                <RelatedDestinations
                  destinations={detectionDestinations}
                  loading={loadingDetectionDestinations}
                />
              }
            />
          </GenericItemCard.ValuesGroup>
          <GenericItemCard.ValuesGroup>
            <Flex ml="auto" mr={0} align="flex-end" spacing={4}>
              <StatusBadge status={policy.complianceStatus} />
              <StatusBadge
                status={policy.enabled ? 'ENABLED' : ComplianceStatusEnum.Error}
                disabled={!policy.enabled}
              />
              <SeverityBadge severity={policy.severity} />
            </Flex>
          </GenericItemCard.ValuesGroup>
        </SimpleGrid>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(PolicyCard);
