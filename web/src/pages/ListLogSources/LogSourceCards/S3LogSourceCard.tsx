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
import flatten from 'lodash/flatten';
import { S3LogIntegration } from 'Generated/schema';
import GenericItemCard from 'Components/GenericItemCard';
import BulletedLogTypeList from 'Components/BulletedLogTypeList';
import { formatDatetime } from 'Helpers/utils';
import s3Logo from 'Assets/s3-minimal-logo.svg';
import LogSourceCard from './LogSourceCard';

interface S3LogSourceCardProps {
  source: S3LogIntegration;
}

const S3LogSourceCard: React.FC<S3LogSourceCardProps> = ({ source }) => {
  const logTypesFlat = React.useMemo(() => {
    return flatten(source.s3PrefixLogTypes.map(({ logTypes }) => logTypes));
  }, [source.s3PrefixLogTypes]);

  return (
    <LogSourceCard logo={s3Logo} source={source}>
      <GenericItemCard.Value label="AWS Account ID" value={source.awsAccountId} />
      <GenericItemCard.Value label="S3 Bucket" value={source.s3Bucket} />
      <GenericItemCard.Value label="S3 Prefix" value={source.s3Prefix} />
      <GenericItemCard.Value label="KMS Key" value={source.kmsKey} />
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Date Created"
        value={formatDatetime(source.createdAtTime, true)}
      />
      <GenericItemCard.LineBreak />
      <GenericItemCard.Value
        label="Log Types"
        value={<BulletedLogTypeList logTypes={logTypesFlat} limit={4} />}
      />
    </LogSourceCard>
  );
};

export default React.memo(S3LogSourceCard);
