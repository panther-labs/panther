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
import { Flex, Tab, Box, BoxProps } from 'pouncejs';

/**
 * These props are automatically passed by `TabList` and not by the developer. At the export level
 * of this component, we "hide" them from the developer by exporting this component `as React.FC`
 */
interface OverviewTabProps {
  /** Whether the tab is selected */
  isSelected: boolean;

  /** Whether the tab is focused */
  isFocused: boolean;
}

const OverviewTab: React.FC<OverviewTabProps> = ({ isSelected, isFocused, children }) => {
  let backgroundColor: BoxProps['backgroundColor'];
  if (isSelected) {
    backgroundColor = 'blue-400';
  } else if (isFocused) {
    backgroundColor = 'navyblue-300';
  } else {
    backgroundColor = 'navyblue-400';
  }

  return (
    <Tab>
      <Box
        mr={4}
        pl={4}
        pr={6}
        py={3}
        borderRadius="pill"
        transition="background-color 200ms cubic-bezier(0.0, 0, 0.2, 1) 0ms"
        backgroundColor={backgroundColor}
        _hover={{
          backgroundColor: !isSelected ? 'navyblue-300' : undefined,
        }}
      >
        <Flex align="center" spacing={3}>
          {children}
        </Flex>
      </Box>
    </Tab>
  );
};

export default React.memo(OverviewTab) as React.FC;
