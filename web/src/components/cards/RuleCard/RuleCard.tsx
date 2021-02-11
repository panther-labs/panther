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
import { Box, Flex, Divider, Link, SimpleGrid } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';
import BulletedValueList from 'Components/BulletedValueList';
import urls from 'Source/urls';
import { ComplianceStatusEnum } from 'Generated/schema';
import { SelectCheckbox } from 'Components/utils/SelectContext';
import { RuleSummary } from 'Source/graphql/fragments/RuleSummary.generated';
import { formatDatetime } from 'Helpers/utils';
import useDetectionDestinations from 'Hooks/useDetectionDestinations';
import RelatedDestinations from 'Components/RelatedDestinations';
import FlatBadge from 'Components/badges/FlatBadge';
import RuleCardOptions from './RuleCardOptions';

interface RuleCardProps {
  rule: RuleSummary;
  selectionEnabled?: boolean;
  isSelected?: boolean;
}

const RuleCard: React.FC<RuleCardProps> = ({
  rule,
  selectionEnabled = false,
  isSelected = false,
}) => {
  const {
    detectionDestinations,
    loading: loadingDetectionDestinations,
  } = useDetectionDestinations({ detection: rule });
  return (
    <GenericItemCard isHighlighted={isSelected}>
      {selectionEnabled && (
        <Box transform="translate3d(-12px,-12px,0)">
          <SelectCheckbox selectionItem={rule} />
        </Box>
      )}
      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            <Link
              as={RRLink}
              aria-label="Link to Rule"
              to={urls.logAnalysis.rules.details(rule.id)}
            >
              {rule.displayName || rule.id}
            </Link>
          </GenericItemCard.Heading>
          <GenericItemCard.HeadingValue
            value={formatDatetime(rule.lastModified)}
            label="Updated"
            labelFirst
          />
          <RuleCardOptions rule={rule} />
        </GenericItemCard.Header>
        <Box mr="auto">
          <FlatBadge color="cyan-500">RULE</FlatBadge>
        </Box>
        <SimpleGrid gap={2} columns={2}>
          <GenericItemCard.Value
            label="Log Types"
            value={<BulletedValueList values={rule.logTypes} limit={3} />}
          />
          <Flex align="flex-end">
            <Flex spacing={2} align="center" width="100%" justify="flex-end">
              <RelatedDestinations
                destinations={detectionDestinations}
                loading={loadingDetectionDestinations}
                limit={3}
              />
              <Divider mx={0} alignSelf="stretch" orientation="vertical"></Divider>
              <StatusBadge
                status={rule.enabled ? 'ENABLED' : ComplianceStatusEnum.Error}
                disabled={!rule.enabled}
              />
              <SeverityBadge severity={rule.severity} />
            </Flex>
          </Flex>
        </SimpleGrid>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(RuleCard);
