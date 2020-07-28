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
import { Flex, Img, Tooltip } from 'pouncejs';

type LogSourceTypeProps = {
  name: string;
  logo: any;
};

const LogSourceType: React.FC<LogSourceTypeProps> = ({ name, logo }) => {
  return (
    <Flex justify="start" align="center">
      <Tooltip content={name}>
        <Img
          src={logo}
          alt={name}
          objectFit="contain"
          nativeHeight={48}
          nativeWidth={48}
          my={-2}
          px={1}
        />
      </Tooltip>
    </Flex>
  );
};

export default React.memo(LogSourceType);
