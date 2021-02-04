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
