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
import GenericItemCard from 'Components/GenericItemCard';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { DESTINATIONS } from 'Source/constants';
import { DestinationTypeEnum } from 'Generated/schema';
import DestinationCard from './DestinationCard';

interface JiraDestinationCardProps {
  destination: DestinationFull;
}

const JiraDestinationCard: React.FC<JiraDestinationCardProps> = ({ destination }) => {
  return (
    <DestinationCard logo={DESTINATIONS[DestinationTypeEnum.Jira].logo} destination={destination}>
      <GenericItemCard.Value
        label="Organization Domain"
        value={destination.outputConfig.jira.orgDomain}
      />
      <GenericItemCard.Value label="Assignee ID" value={destination.outputConfig.jira.assigneeId} />
      <GenericItemCard.Value label="Issue Type" value={destination.outputConfig.jira.issueType} />
    </DestinationCard>
  );
};

export default React.memo(JiraDestinationCard);
