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
import { Flex, Link, Badge, Box } from 'pouncejs';
import { DataModel } from 'Generated/schema';
import GenericItemCard from 'Components/GenericItemCard';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import { formatDatetime } from 'Helpers/utils';
import BulletedValue from 'Components/BulletedValue';
import { SelectCheckbox } from 'Components/utils/SelectContext';
import DataModelCardOptions from './DataModelCardOptions';

interface DataModelCardProps {
  dataModel: DataModel;
  selectionEnabled?: boolean;
  isSelected?: boolean;
}

const DataModelCard: React.FC<DataModelCardProps> = ({
  dataModel,
  isSelected = false,
  selectionEnabled = false,
}) => {
  return (
    <GenericItemCard isHighlighted={isSelected}>
      {selectionEnabled && (
        <Box transform="translate3d(-12px,-12px,0)">
          <SelectCheckbox selectionItem={dataModel} />
        </Box>
      )}
      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            <Link as={RRLink} to={urls.logAnalysis.dataModels.details(dataModel.id)}>
              {dataModel.displayName || dataModel.id}
            </Link>
          </GenericItemCard.Heading>
          <GenericItemCard.HeadingValue label="ID" value={dataModel.id} labelFirst withDivider />
          <GenericItemCard.HeadingValue
            value={formatDatetime(dataModel.lastModified)}
            label="Updated"
            labelFirst
          />
          <DataModelCardOptions dataModel={dataModel} />
        </GenericItemCard.Header>

        <GenericItemCard.ValuesGroup>
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
