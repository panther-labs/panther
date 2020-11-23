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
import { Flex, Tooltip, Box } from 'pouncejs';
import NotificationJewel from 'Components/NotificationJewel';

interface LimitItemDisplayProps {
  /**
   * How many items should we show before we limit them
   */
  limit: number;

  /**
   * @ignore
   */
  children: React.ReactNode | React.ReactNode[];
}

const LimitItemDisplay: React.FC<LimitItemDisplayProps> = ({ limit, children }) => {
  const childrenCount = React.Children.count(children);
  if (childrenCount <= limit) {
    return children as any;
  }

  const childrenList = React.Children.toArray(children);
  const displayedChildren = childrenList.slice(0, limit);
  const hiddenChildren = childrenList.slice(limit);

  return (
    <React.Fragment>
      {displayedChildren}
      <Tooltip
        content={
          <Flex direction="column" spacing={1}>
            {hiddenChildren}
          </Flex>
        }
      >
        <Box>
          <NotificationJewel badge={`+${childrenCount - limit}`} />
        </Box>
      </Tooltip>
    </React.Fragment>
  );
};

export default React.memo(LimitItemDisplay);
