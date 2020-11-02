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
import { Box, Flex } from 'pouncejs';
import { SqsLogSourceIntegration } from 'Generated/schema';
import GenericItemCard from 'Components/GenericItemCard';
import LimitItemDisplay from 'Components/LimitItemDisplay';
import { formatDatetime } from 'Helpers/utils';
import sqsLogo from 'Assets/sqs-minimal-logo.svg';
import BulletedLogType from 'Components/BulletedLogType';
import LogSourceCard from './LogSourceCard';

interface SqsLogSourceCardProps {
  source: SqsLogSourceIntegration;
}

const SqsLogSourceCard: React.FC<SqsLogSourceCardProps> = ({ source }) => {
  return (
    <LogSourceCard logo={sqsLogo} source={source}>
      <GenericItemCard.Value label="SQS Queue URL" value={source.sqsConfig.queueUrl} />
      <GenericItemCard.Value
        label="Allowed Principal ARNs"
        value={
          source.sqsConfig.allowedPrincipalArns.length ? (
            <React.Fragment>
              {source.sqsConfig.allowedPrincipalArns.map(arn => (
                <Box key={arn}>{arn}</Box>
              ))}
            </React.Fragment>
          ) : null
        }
      />
      <GenericItemCard.Value
        label="Allowed Source ARNs"
        value={
          source.sqsConfig.allowedSourceArns.length ? (
            <React.Fragment>
              {source.sqsConfig.allowedSourceArns.map(arn => (
                <Box key={arn}>{arn}</Box>
              ))}
            </React.Fragment>
          ) : null
        }
      />
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Date Created"
        value={formatDatetime(source.createdAtTime, true)}
      />
      <GenericItemCard.Value
        label="Last Received Events At"
        value={source.lastEventReceived ? formatDatetime(source.lastEventReceived, true) : 'Never'}
      />
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Log Types"
        value={
          <Flex align="center" spacing={4} mt={1}>
            <LimitItemDisplay limit={4}>
              {source.sqsConfig.logTypes.map(logType => (
                <BulletedLogType key={logType} logType={logType} />
              ))}
            </LimitItemDisplay>
          </Flex>
        }
      />
    </LogSourceCard>
  );
};

export default SqsLogSourceCard;
