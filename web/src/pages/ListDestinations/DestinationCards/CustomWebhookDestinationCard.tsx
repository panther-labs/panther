import React from 'react';
import GenericItemCard from 'Components/GenericItemCard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { formatDatetime } from 'Helpers/utils';
import { DESTINATIONS } from 'Source/constants';
import { DestinationTypeEnum } from 'Generated/schema';
import DestinationCard from './DestinationCard';

interface CustomWebhookDestinationCardProps {
  destination: DestinationFull;
}

const CustomWebhookDestinationCard: React.FC<CustomWebhookDestinationCardProps> = ({
  destination,
}) => {
  return (
    <DestinationCard
      key={destination.outputId}
      logo={DESTINATIONS[DestinationTypeEnum.Customwebhook].logo}
      destination={destination}
    >
      <GenericItemCard.Value
        label="Webhook URL"
        value={destination.outputConfig.customWebhook.webhookURL}
      />
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

export default React.memo(CustomWebhookDestinationCard);
