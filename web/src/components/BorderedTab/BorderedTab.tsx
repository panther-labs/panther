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
import { Heading, HeadingProps, Tab } from 'pouncejs';

/**
 * These props are automatically passed by `TabList` and not by the developer. At the export level
 * of this component, we "hide" them from the developer byy exporting this component `as React.FC`
 */
interface PrivateBorderedTabProps {
  /** Whether the tab is selected */
  isSelected: boolean;

  /** Whether the tab is focused */
  isFocused: boolean;
}

const BorderedTab: React.FC<PrivateBorderedTabProps> = ({ isSelected, isFocused, children }) => {
  const selectedColor = 'blue-400';
  const focusedColor = 'navyblue-300';

  let borderColor: HeadingProps['borderColor'];
  if (isSelected) {
    borderColor = selectedColor;
  } else if (isFocused) {
    borderColor = focusedColor;
  } else {
    borderColor = 'transparent';
  }

  return (
    <Tab>
      <Heading
        size="x-small"
        as="h4"
        borderBottom="3px solid"
        zIndex={5}
        mx={4}
        py={6}
        transition="border-color 200ms cubic-bezier(0.0, 0, 0.2, 1) 0ms"
        borderColor={borderColor}
        _hover={{
          borderColor: !isSelected ? focusedColor : undefined,
        }}
      >
        {children}
      </Heading>
    </Tab>
  );
};

export default React.memo(BorderedTab) as React.FC;
