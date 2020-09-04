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
import { Link as RRLink } from 'react-router-dom';
import GenericItemCard from 'Components/GenericItemCard';
import { LogIntegration } from 'Generated/schema';
import { PANTHER_USER_ID } from 'Source/constants';
import urls from 'Source/urls';
import SourceHealthBadge from 'Components/badges/SourceHealthBadge';
import LogSourceCardOptions from './LogSourceCardOptions';

interface LogSourceCardProps {
  source: LogIntegration;
  logo: string;
  children: React.ReactNode;
}

const LogSourceCard: React.FC<LogSourceCardProps> = ({ source, children, logo }) => {
  const isCreatedByPanther = source.createdBy === PANTHER_USER_ID;
  const { health: sourceHealth } = source;

  const healthMetrics = React.useMemo(() => {
    switch (sourceHealth.__typename) {
      case 'SqsLogIntegrationHealth':
        return [sourceHealth.sqsStatus];
      case 'S3LogIntegrationHealth':
        return [
          sourceHealth.processingRoleStatus,
          sourceHealth.s3BucketStatus,
          sourceHealth.kmsKeyStatus,
        ];
      default:
        throw new Error(`Unknown source health item`);
    }
  }, [sourceHealth]);

  return (
    <GenericItemCard>
      <GenericItemCard.Logo src={logo} />
      {!isCreatedByPanther && <LogSourceCardOptions source={source} />}
      <GenericItemCard.Body>
        <Link
          as={RRLink}
          to={urls.logAnalysis.sources.edit(source.integrationId, 'sqs')}
          cursor="pointer"
        >
          <GenericItemCard.Heading>{source.integrationLabel}</GenericItemCard.Heading>
        </Link>
        <GenericItemCard.ValuesGroup>
          {children}
          <Flex ml="auto" mr={0} align="flex-end">
            <SourceHealthBadge healthMetrics={healthMetrics} />
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default LogSourceCard;
