import React from 'react';
import GenericItemCard from 'Components/GenericItemCard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { formatDatetime } from 'Helpers/utils';
import { DESTINATIONS } from 'Source/constants';
import { DestinationTypeEnum } from 'Generated/schema';
import DestinationCard from './DestinationCard';

interface GithubDestinationCardProps {
  destination: DestinationFull;
}

const GithubDestinationCard: React.FC<GithubDestinationCardProps> = ({ destination }) => {
  return (
    <DestinationCard
      key={destination.outputId}
      logo={DESTINATIONS[DestinationTypeEnum.Github].logo}
      destination={destination}
    >
      <GenericItemCard.Value label="Repository" value={destination.outputConfig.github.repoName} />
      <br />
      <GenericItemCard.Value
        label="Date Created"
        value={formatDatetime(destination.creationTime, true)}
      />
      <GenericItemCard.Value
        label="Last Updated"
        value={formatDatetime(destination.lastModifiedTime, true)}
      />
    </DestinationCard>
  );
};

export default React.memo(GithubDestinationCard);
