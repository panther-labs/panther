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

const NotificationJewel: React.FC<{ badge: string | React.ReactNode }> = ({ badge }) => {
  return (
    <Flex
      justify="center"
      align="center"
      width={18}
      height={18}
      backgroundColor="navyblue-200"
      borderRadius="circle"
      fontSize="2x-small"
      fontWeight="medium"
      cursor="default"
    >
      {badge}
    </Flex>
  );
};

export default React.memo(NotificationJewel);
