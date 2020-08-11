import GenericItemCard from 'Components/GenericItemCard';
import { Flex } from 'pouncejs';
import SeverityBadge from 'Components/SeverityBadge';
import React from 'react';
import DestinationCardOptions from 'Pages/ListDestinations/DestinationCards/DestinationCardOptions';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';

interface DestinationCardProps {
  destination: DestinationFull;
  logo: string;
  children: React.ReactNode;
}

const DestinationCard: React.FC<DestinationCardProps> = ({ destination, logo, children }) => {
  return (
    <GenericItemCard key={destination.outputId}>
      <GenericItemCard.Logo src={logo} />
      <DestinationCardOptions destination={destination} />
      <GenericItemCard.Body>
        <GenericItemCard.Heading>{destination.displayName}</GenericItemCard.Heading>
        {children}
        <Flex spacing={2} mt={2}>
          {destination.defaultForSeverity.map(severity => (
            <SeverityBadge severity={severity} key={severity} />
          ))}
        </Flex>
      </GenericItemCard.Body>
    </GenericItemCard>
  );
};

export default React.memo(DestinationCard);
