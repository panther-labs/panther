/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2021 Panther Labs Inc
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
import { ListComplianceSources } from '../graphql/listComplianceSources.generated';
import ComplianceSourceCard from '../ComplianceSourceCard';

type ListDestinationsTableProps = { sources: ListComplianceSources['listComplianceIntegrations'] };

const ListDestinationsCards: React.FC<ListDestinationsTableProps> = ({ sources }) => {
  return (
    <SimpleGrid as="article" columns={1} gap={5}>
      {sources.map(source => (
        <ComplianceSourceCard key={source.integrationId} source={source} />
      ))}
    </SimpleGrid>
  );
};

export default React.memo(ListDestinationsCards);
