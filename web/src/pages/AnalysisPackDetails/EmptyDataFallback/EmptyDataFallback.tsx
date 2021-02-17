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
import { Flex, Heading } from 'pouncejs';
import EmptyBoxImg from 'Assets/illustrations/empty-box.svg';

const EmptyDataFallback: React.FC<{ message: string }> = ({ message }) => {
  return (
    <Flex justify="center" align="center" direction="column" my={8} spacing={8}>
      <img alt="Empty Box Illustration" src={EmptyBoxImg} width="auto" height={200} />
      <Heading size="small" color="navyblue-100">
        {message}
      </Heading>
    </Flex>
  );
};

export default React.memo(EmptyDataFallback);
