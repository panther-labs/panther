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
import { Box, BoxProps, useTheme } from 'pouncejs';

type BulletedLoadingProps = BoxProps;

const BulletedLoading: React.FC<BulletedLoadingProps> = props => {
  const theme = useTheme();

  return (
    <Box
      as="svg"
      width={75}
      height={20}
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 100 20"
      preserveAspectRatio="xMidYMid"
      aria-label="Loading Animation"
      {...props}
    >
      <g transform="translate(25 10)">
        <circle cx="0" cy="0" r="8" fill={theme.colors['navyblue-100']} opacity="0.1">
          <animateTransform
            attributeName="transform"
            type="scale"
            begin="-0.3333333333333333s"
            calcMode="spline"
            keySplines="0.3 0 0.7 1;0.3 0 0.7 1"
            values="0;1;0"
            keyTimes="0;0.5;1"
            dur="1s"
            repeatCount="indefinite"
          />
        </circle>
      </g>
      <g transform="translate(50 10)">
        <circle cx="0" cy="0" r="8" fill={theme.colors['navyblue-100']} opacity="0.3">
          <animateTransform
            attributeName="transform"
            type="scale"
            begin="-0.16666666666666666s"
            calcMode="spline"
            keySplines="0.3 0 0.7 1;0.3 0 0.7 1"
            values="0;1;0"
            keyTimes="0;0.5;1"
            dur="1s"
            repeatCount="indefinite"
          />
        </circle>
      </g>
      <g transform="translate(75 10)">
        <circle cx="0" cy="0" r="8" fill={theme.colors['navyblue-100']}>
          <animateTransform
            attributeName="transform"
            type="scale"
            begin="0s"
            calcMode="spline"
            keySplines="0.3 0 0.7 1;0.3 0 0.7 1"
            values="0;1;0"
            keyTimes="0;0.5;1"
            dur="1s"
            repeatCount="indefinite"
          />
        </circle>
      </g>
    </Box>
  );
};

export default BulletedLoading;
