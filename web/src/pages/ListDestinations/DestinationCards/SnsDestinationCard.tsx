import React from 'react';
import GenericItemCard from 'Components/GenericItemCard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { formatDatetime } from 'Helpers/utils';
import { DESTINATIONS } from 'Source/constants';
import { DestinationTypeEnum } from 'Generated/schema';
import DestinationCard from './DestinationCard';

interface SnsDestinationCardProps {
  destination: DestinationFull;
}

const SnsDestinationCard: React.FC<SnsDestinationCardProps> = ({ destination }) => {
  return (
    <DestinationCard
      key={destination.outputId}
      logo={DESTINATIONS[DestinationTypeEnum.Sns].logo}
      destination={destination}
    >
      <GenericItemCard.ValuesGroup>
        <GenericItemCard.Value label="Topic ARN" value={destination.outputConfig.sns.topicArn} />
        <GenericItemCard.Value
          label="Date Created"
          value={formatDatetime(destination.creationTime, true)}
        />
        <GenericItemCard.Value
          label="Last Updated"
          value={formatDatetime(destination.lastModifiedTime, true)}
        />
      </GenericItemCard.ValuesGroup>
    </DestinationCard>
  );
};

export default React.memo(SnsDestinationCard);
