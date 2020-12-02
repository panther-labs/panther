/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
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
