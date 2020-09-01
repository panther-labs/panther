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
import { S3LogIntegration, SqsLogSourceIntegration } from 'Generated/schema';
import { LogIntegrationsEnum } from 'Source/constants';
import { ListLogSources } from '../graphql/listLogSources.generated';
import { S3LogSourceCard, SqsLogSourceCard } from '../LogSourceCards';

type ListLogSourceCardsProps = { sources: ListLogSources['listLogIntegrations'] };

const ListLogSourceCards: React.FC<ListLogSourceCardsProps> = ({ sources }) => {
  return (
    <SimpleGrid as="article" columns={1} gap={5}>
      {sources.map(source => {
        const { integrationId, integrationType } = source;
        switch (integrationType) {
          case LogIntegrationsEnum.sqs:
            return (
              <SqsLogSourceCard source={source as SqsLogSourceIntegration} key={integrationId} />
            );
          case LogIntegrationsEnum.s3:
            return <S3LogSourceCard source={source as S3LogIntegration} key={integrationId} />;
          default:
            throw new Error(`No Card matching found for ${integrationType}`);
        }
      })}
    </SimpleGrid>
  );
};

export default React.memo(ListLogSourceCards);
