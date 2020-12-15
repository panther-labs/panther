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
import { Link } from 'pouncejs';
import GenericItemCard from 'Components/GenericItemCard';
import { Link as RRLink } from 'react-router-dom';
import { formatDatetime } from 'Helpers/utils';
import urls from 'Source/urls';
import { ListCustomLogSchemas } from '../graphql/listCustomLogSchemas.generated';
import CustomLogCardOptions from './CustomLogCardOptions';

interface CustomLogCardProps {
  customLog: ListCustomLogSchemas['listCustomLogs'][0];
}

const CustomLogCard: React.FC<CustomLogCardProps> = ({ customLog }) => {
  return (
    <GenericItemCard>
      <GenericItemCard.Body>
        <GenericItemCard.Header>
          <GenericItemCard.Heading>
            <Link
              as={RRLink}
              to={urls.logAnalysis.customLogs.details(customLog.logType)}
              cursor="pointer"
            >
              {customLog.logType}
            </Link>
          </GenericItemCard.Heading>
          <CustomLogCardOptions customLog={customLog} />
        </GenericItemCard.Header>
        <GenericItemCard.ValuesGroup>
          <GenericItemCard.Value label="Description" value={customLog.description} />
          <GenericItemCard.Value label="Reference URL" value={customLog.referenceURL} />
          <GenericItemCard.Value
            label="Updated At"
            value={formatDatetime(customLog.updatedAt, true)}
          />
        </GenericItemCard.ValuesGroup>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default CustomLogCard;
