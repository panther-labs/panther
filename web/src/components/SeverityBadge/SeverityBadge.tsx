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
import { Badge, BadgeProps } from 'pouncejs';
import { SeverityEnum } from 'Generated/schema';

export const SEVERITY_COLOR_MAP: { [key in SeverityEnum]: BadgeProps['color'] } = {
  [SeverityEnum.Critical]: 'red-500' as const,
  [SeverityEnum.High]: 'orange-400' as const,
  [SeverityEnum.Medium]: 'yellow-500' as const,
  [SeverityEnum.Low]: 'gray-500' as const,
  [SeverityEnum.Info]: 'gray-600' as const,
};

interface SeverityBadgeProps {
  severity: SeverityEnum;
}

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  return (
    <Badge variant="outline" color={SEVERITY_COLOR_MAP[severity]}>
      {severity}
    </Badge>
  );
};

export default SeverityBadge;
