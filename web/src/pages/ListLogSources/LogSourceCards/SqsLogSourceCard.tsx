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
import { Box } from 'pouncejs';
import { SqsLogSourceIntegration } from 'Generated/schema';
import GenericItemCard from 'Components/GenericItemCard';
import BulletedValueList from 'Components/BulletedValueList';
import { formatDatetime } from 'Helpers/utils';
import sqsLogo from 'Assets/sqs-minimal-logo.svg';
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
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Log Types"
        value={<BulletedValueList values={source.sqsConfig.logTypes} limit={4} />}
      />
    </LogSourceCard>
  );
};

export default SqsLogSourceCard;
