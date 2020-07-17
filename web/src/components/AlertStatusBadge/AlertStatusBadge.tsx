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
import { Badge, BadgeProps, PseudoBox, Flex, Icon, Box } from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';

const STATUS_COLOR_MAP: {
  [key in StatusBadgeProps['status']]: BadgeProps['color'];
} = {
  [AlertStatusesEnum.Open]: 'red-200' as const,
  [AlertStatusesEnum.Triaged]: 'yellow-500' as const,
  [AlertStatusesEnum.Closed]: 'navyblue-550' as const,
  [AlertStatusesEnum.Resolved]: 'navyblue-500' as const,
};

interface StatusBadgeProps {
  status: AlertStatusesEnum;
}

const AlertStatusBadge: React.FC<StatusBadgeProps> = ({ status }) => (
  <PseudoBox role="group">
    <Flex spacing={1} justify="center" align="center">
      <PseudoBox
        as={Badge}
        backgroundColor={STATUS_COLOR_MAP[status]}
        cursor="pointer"
        padding="4px 4px 4px 4px"
      >
        <Box>{status}</Box>
      </PseudoBox>
      <PseudoBox
        as={Icon}
        type="caret-down"
        padding={1}
        transition="all 0.2s ease-in-out"
        border="1px solid"
        borderColor="navyblue-450"
        borderRadius="pill"
        backgroundColor="transparent"
        cursor="pointer"
        _groupHover={{ backgroundColor: 'navyblue-450' }}
      />
    </Flex>
  </PseudoBox>
);

export default AlertStatusBadge;
