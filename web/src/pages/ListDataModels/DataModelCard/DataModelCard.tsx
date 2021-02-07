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
import { Flex, Link, Badge } from 'pouncejs';
import { DataModel } from 'Generated/schema';
import GenericItemCard from 'Components/GenericItemCard';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { formatDatetime } from 'Helpers/utils';
import BulletedValue from 'Components/BulletedValue';
import DataModelCardOptions from './DataModelCardOptions';

interface DataModelCardProps {
  dataModel: DataModel;
}

const DataModelCard: React.FC<DataModelCardProps> = ({ dataModel }) => {
  return (
    <GenericItemCard>
      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            <Link as={RRLink} to={urls.logAnalysis.dataModels.details(dataModel.id)}>
              {dataModel.displayName || dataModel.id}
            </Link>
          </GenericItemCard.Heading>
          <GenericItemCard.Date date={formatDatetime(dataModel.lastModified)} />
          <DataModelCardOptions dataModel={dataModel} />
        </GenericItemCard.Header>

        <GenericItemCard.ValuesGroup>
          <GenericItemCard.Value label="ID" value={dataModel.id} />
          <GenericItemCard.Value
            label="Log Type"
            value={<BulletedValue value={dataModel.logTypes[0]} />}
          />
          <Flex ml="auto" mr={0} align="flex-end" spacing={4}>
            <Badge color={dataModel.enabled ? 'cyan-400' : 'navyblue-300'}>
              {dataModel.enabled ? 'ENABLED' : 'DISABLED'}
            </Badge>
          </Flex>
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(DataModelCard);
