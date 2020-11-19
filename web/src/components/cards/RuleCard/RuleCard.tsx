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
import { Flex, Link, SimpleGrid } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import SeverityBadge from 'Components/badges/SeverityBadge';
import StatusBadge from 'Components/badges/StatusBadge';
import BulletedLogTypeList from 'Components/BulletedLogTypeList';
import urls from 'Source/urls';
import { RuleSummary, ComplianceStatusEnum } from 'Generated/schema';
import { formatDatetime } from 'Helpers/utils';
import useDetectionDestinations from 'Hooks/useDetectionDestinations';
import RelatedDestinations from 'Components/RelatedDestinations';
import RuleCardOptions from './RuleCardOptions';

interface RuleCardProps {
  rule: RuleSummary;
}

const RuleCard: React.FC<RuleCardProps> = ({ rule }) => {
  const {
    detectionDestinations,
    loading: loadingDetectionDestinations,
  } = useDetectionDestinations({ rule });
  return (
    <GenericItemCard>
      <GenericItemCard.Options>
        <GenericItemCard.Date date={formatDatetime(rule.lastModified)} />
        <RuleCardOptions rule={rule} />
      </GenericItemCard.Options>
      <GenericItemCard.Body>
        <Flex align="center">
          <GenericItemCard.Heading>
            <Link
              as={RRLink}
              aria-label="Link to Rule"
              to={urls.logAnalysis.rules.details(rule.id)}
            >
              {rule.displayName || rule.id}
            </Link>
          </GenericItemCard.Heading>
        </Flex>

        <SimpleGrid gap={2} columns={2}>
          <GenericItemCard.ValuesGroup>
            <GenericItemCard.Value
              label="Log Types"
              value={<BulletedLogTypeList logTypes={rule.logTypes} limit={2} />}
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
              <StatusBadge
                status={rule.enabled ? 'ENABLED' : ComplianceStatusEnum.Error}
                disabled={!rule.enabled}
              />
              <SeverityBadge severity={rule.severity} />
            </Flex>
          </GenericItemCard.ValuesGroup>
        </SimpleGrid>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(RuleCard);
