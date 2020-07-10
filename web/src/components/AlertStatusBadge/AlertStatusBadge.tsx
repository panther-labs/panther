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
import { Badge, BadgeProps, PseudoBox } from 'pouncejs';
import { AlertStatusesEnum } from 'Generated/schema';

const STATUS_COLOR_MAP: {
  [key in StatusBadgeProps['status']]: BadgeProps['color'];
} = {
  [AlertStatusesEnum.Open]: 'yellow-500' as const,
  [AlertStatusesEnum.Triaged]: 'orange-500' as const,
  [AlertStatusesEnum.Closed]: 'teal-300' as const,
  [AlertStatusesEnum.Resolved]: 'green-200' as const,
};

interface StatusBadgeProps {
  status: AlertStatusesEnum;
  disabled?: boolean;
}

const AlertStatusBadge: React.FC<StatusBadgeProps> = ({ status, disabled = false }) => {
  if (disabled) {
    return (
      <PseudoBox as={Badge} opacity={0.5} backgroundColor="gray-800">
        {status}
      </PseudoBox>
    );
  }

  return (
    <PseudoBox
      as={Badge}
      transition="box-shadow 0.2s ease-in-out"
      backgroundColor={STATUS_COLOR_MAP[status]}
      cursor="pointer"
      _hover={{
        boxShadow: '0px 0px 10px rgba(255, 255, 255, .3)',
      }}
    >
      {status}
    </PseudoBox>
  );
};

export default AlertStatusBadge;
