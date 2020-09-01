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
import { SimpleGrid } from 'pouncejs';
import { DestinationTypeEnum } from 'Generated/schema';
import { ListDestinationsAndDefaults } from '../graphql/listDestinationsAndDefaults.generated';
import {
  MsTeamsDestinationCard,
  AsanaDestinationCard,
  SlackDestinationCard,
  SnsDestinationCard,
  CustomWebhookDestinationCard,
  GithubDestinationCard,
  JiraDestinationCard,
  OpsGenieDestinationCard,
  PagerDutyDestinationCard,
  SqsDestinationCard,
} from '../DestinationCards';

type ListDestinationsTableProps = Pick<ListDestinationsAndDefaults, 'destinations'>;

const ListDestinationsCards: React.FC<ListDestinationsTableProps> = ({ destinations }) => {
  return (
    <SimpleGrid as="article" columns={1} gap={5}>
      {destinations.map(destination => {
        const { outputId } = destination;
        switch (destination.outputType) {
          case DestinationTypeEnum.Slack:
            return <SlackDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Msteams:
            return <MsTeamsDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Asana:
            return <AsanaDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Sns:
            return <SnsDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Sqs:
            return <SqsDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Github:
            return <GithubDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Jira:
            return <JiraDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Opsgenie:
            return <OpsGenieDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Pagerduty:
            return <PagerDutyDestinationCard destination={destination} key={outputId} />;
          case DestinationTypeEnum.Customwebhook:
            return <CustomWebhookDestinationCard destination={destination} key={outputId} />;
          default:
            throw new Error(`No Card matching found for ${destination.outputType}`);
        }
      })}
    </SimpleGrid>
  );
};

export default React.memo(ListDestinationsCards);
