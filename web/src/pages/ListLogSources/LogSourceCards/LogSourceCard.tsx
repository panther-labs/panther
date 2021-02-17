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
import { Link as RRLink } from 'react-router-dom';
import GenericItemCard from 'Components/GenericItemCard';
import { LogIntegration } from 'Generated/schema';
import { PANTHER_USER_ID } from 'Source/constants';
import urls from 'Source/urls';
import SourceHealthBadge from 'Components/badges/SourceHealthBadge';
import { getElapsedTime } from 'Helpers/utils';
import LogSourceCardOptions from './LogSourceCardOptions';

interface LogSourceCardProps {
  source: LogIntegration;
  logo: string;
  children: React.ReactNode;
}

const LogSourceCard: React.FC<LogSourceCardProps> = ({ source, children, logo }) => {
  const isCreatedByPanther = source.createdBy === PANTHER_USER_ID;
  const { health: sourceHealth } = source;

  const sourceType = React.useMemo(() => {
    switch (source.__typename) {
      case 'SqsLogSourceIntegration':
        return 'sqs';
      case 'S3LogIntegration':
        return 's3';
      default:
        throw new Error(`Unknown source health item`);
    }
  }, [source]);

  const healthMetrics = React.useMemo(() => {
    switch (sourceHealth.__typename) {
      case 'SqsLogIntegrationHealth':
        return [sourceHealth.sqsStatus];
      case 'S3LogIntegrationHealth': {
        const checks = [
          sourceHealth.processingRoleStatus,
          sourceHealth.s3BucketStatus,
          sourceHealth.kmsKeyStatus,
        ];
        if (sourceHealth.getObjectStatus) {
          checks.push(sourceHealth.getObjectStatus);
        }
        return checks;
      }
      default:
        throw new Error(`Unknown source health item`);
    }
  }, [sourceHealth]);

  const lastReceivedMessage = React.useMemo(() => {
    return source.lastEventReceived
      ? `${getElapsedTime(new Date(source.lastEventReceived).getTime() / 1000)}`
      : 'No Data Received yet';
  }, [source.lastEventReceived]);

  return (
    <GenericItemCard>
      <GenericItemCard.Logo src={logo} />

      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            {!isCreatedByPanther ? (
              <Link
                as={RRLink}
                to={urls.integrations.logSources.edit(source.integrationId, sourceType)}
              >
                {source.integrationLabel}
              </Link>
            ) : (
              <Tooltip content="This is a log source we created for you.">
                <Text color="teal-300" as="span">
                  {source.integrationLabel}
                </Text>
              </Tooltip>
            )}
          </GenericItemCard.Heading>
          <GenericItemCard.HeadingValue
            value={lastReceivedMessage}
            label={source.lastEventReceived ? 'Last Received Data' : null}
            labelFirst
          />
          {!isCreatedByPanther && <LogSourceCardOptions source={source} />}
        </GenericItemCard.Header>
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
