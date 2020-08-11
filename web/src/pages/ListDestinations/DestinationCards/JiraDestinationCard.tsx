import React from 'react';
import GenericItemCard from 'Components/GenericItemCard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { formatDatetime } from 'Helpers/utils';
import { DESTINATIONS } from 'Source/constants';
import { DestinationTypeEnum } from 'Generated/schema';
import DestinationCard from './DestinationCard';

interface JiraDestinationCardProps {
  destination: DestinationFull;
}

const JiraDestinationCard: React.FC<JiraDestinationCardProps> = ({ destination }) => {
  return (
    <DestinationCard
      key={destination.outputId}
      logo={DESTINATIONS[DestinationTypeEnum.Jira].logo}
      destination={destination}
    >
      <GenericItemCard.ValuesGroup>
        <GenericItemCard.Value
          label="Organization Domain"
          value={destination.outputConfig.jira.orgDomain}
        />
        <GenericItemCard.Value
          label="Project Key"
          value={destination.outputConfig.jira.projectKey}
        />
        <GenericItemCard.Value label="Email" value={destination.outputConfig.jira.userName} />
        <GenericItemCard.Value
          label="Assignee ID"
          value={destination.outputConfig.jira.assigneeId}
        />
        <GenericItemCard.Value label="Issue Type" value={destination.outputConfig.jira.issueType} />
        <GenericItemCard.Value
          label="Date Created"
          value={formatDatetime(destination.creationTime)}
        />
        <GenericItemCard.Value
          label="Last Updated"
          value={formatDatetime(destination.lastModifiedTime)}
        />
      </GenericItemCard.ValuesGroup>
    </DestinationCard>
  );
};

export default React.memo(JiraDestinationCard);
