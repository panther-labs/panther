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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import TablePlaceholder from 'Components/TablePlaceholder';
import { Card, FadeIn, Flex, Text } from 'pouncejs';
import Panel from 'Components/Panel/Panel';

const ListSavedQueriesPageSkeleton: React.FC = () => {
  return (
    <FadeIn from="bottom">
      <Panel
        title={
          <Flex align="center" spacing={2} ml={4}>
            <Text>Packs</Text>
          </Flex>
        }
      >
        <Card as="section" position="relative">
          <TablePlaceholder rowCount={5} rowHeight={30} />
        </Card>
      </Panel>
    </FadeIn>
  );
};

export default ListSavedQueriesPageSkeleton;
