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
import { Flex } from 'pouncejs';
import LimitItemDisplay from 'Components/LimitItemDisplay/LimitItemDisplay';
import BulletedLogType from 'Components/BulletedLogType';

interface BulletedLogTypeListProps {
  logTypes: string[];
  limit?: number;
}

const BulletedLogTypeList: React.FC<BulletedLogTypeListProps> = ({ logTypes, limit = 1000 }) => {
  return (
    <Flex align="center" spacing={2} flexWrap="wrap">
      <LimitItemDisplay limit={limit}>
        {logTypes.map(logType => (
          <BulletedLogType key={logType} logType={logType} />
        ))}
      </LimitItemDisplay>
    </Flex>
  );
};

export default React.memo(BulletedLogTypeList);
