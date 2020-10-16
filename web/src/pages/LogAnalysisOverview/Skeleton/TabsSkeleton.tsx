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
import { Box, Card, SimpleGrid, TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import TablePlaceholder from 'Components/TablePlaceholder';

interface Tab {
  label: string;
  loadingComponent?: HTMLHtmlElement;
  height?: number;
}
interface TabSkeletonProps {
  tabs: Tab[];
}

const TabsSkeleton: React.FC<TabSkeletonProps> = ({ tabs }) => {
  return (
    <SimpleGrid columns={1} spacingX={3} spacingY={2} mb={3}>
      <Card as="section">
        <Tabs>
          <Box position="relative" pl={2} pr={4}>
            <TabList>
              {tabs.map(({ label }, i) => (
                <BorderedTab key={i}>{label}</BorderedTab>
              ))}
            </TabList>
            <BorderTabDivider />
          </Box>
          <Box p={6}>
            <TabPanels>
              {tabs.map(({ height = 200 }, i) => (
                <TabPanel key={i} unmountWhenInactive lazy>
                  <Box height={height}>
                    <TablePlaceholder />
                  </Box>
                </TabPanel>
              ))}
            </TabPanels>
          </Box>
        </Tabs>
      </Card>
    </SimpleGrid>
  );
};

export default TabsSkeleton;
