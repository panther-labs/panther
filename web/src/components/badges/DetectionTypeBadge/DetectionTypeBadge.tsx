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
import { Box } from 'pouncejs';
import { DETECTION_TYPE_COLOR_MAP } from 'Source/constants';
import { DetectionTypeEnum } from 'Generated/schema';

type DetectionTypes = DetectionTypeEnum | 'GLOBAL';

interface DetectionTypeBadgeProps {
  count?: number;
  type: DetectionTypes;
}

const detectionTypeTextMap: {
  [key in DetectionTypes]: { single: string; plural: string };
} = {
  GLOBAL: { single: 'HELPER', plural: 'HELPERS' },
  RULE: { single: 'RULE', plural: 'RULES' },
  POLICY: { single: 'POLICY', plural: 'POLICIES' },
};

const DetectionTypeBadge: React.FC<DetectionTypeBadgeProps> = ({ count, type }) => {
  return (
    <Box
      backgroundColor="navyblue-700"
      borderRadius="small"
      px={1}
      py={1}
      fontWeight="bold"
      fontSize="x-small"
      color={DETECTION_TYPE_COLOR_MAP[type]}
    >
      {count
        ? `${count} ${
            count > 1 ? detectionTypeTextMap[type].plural : detectionTypeTextMap[type].single
          }`
        : detectionTypeTextMap[type].single}
    </Box>
  );
};

export default DetectionTypeBadge;
