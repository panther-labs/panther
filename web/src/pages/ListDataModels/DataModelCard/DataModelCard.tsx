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
              {dataModel.displayName}
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
