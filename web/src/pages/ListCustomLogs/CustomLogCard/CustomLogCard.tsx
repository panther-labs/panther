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
import { Link, Text } from 'pouncejs';
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
          {customLog.referenceURL && (
            <GenericItemCard.HeadingValue
              value={
                <Link external href={customLog.referenceURL}>
                  {customLog.referenceURL}
                </Link>
              }
              label="Reference URL"
              labelFirst
              withDivider
            />
          )}
          <GenericItemCard.HeadingValue
            value={formatDatetime(customLog.updatedAt)}
            label="Updated"
            labelFirst
          />
          <CustomLogCardOptions customLog={customLog} />
        </GenericItemCard.Header>
        <Text fontSize="small">{customLog.description}</Text>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default CustomLogCard;
