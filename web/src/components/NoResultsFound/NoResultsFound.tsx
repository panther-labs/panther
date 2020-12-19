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
import { Text, Flex, Img } from 'pouncejs';
import NothingFound from 'Assets/illustrations/nothing-found.svg';

interface NoResultsFoundProps {
  title?: string;
}

const NoResultsFound: React.FC<NoResultsFoundProps> = ({ title = 'No Results' }) => {
  return (
    <Flex justify="center">
      <Flex
        direction="column"
        align="center"
        justify="center"
        backgroundColor="navyblue-500"
        borderRadius="circle"
        width={260}
        height={260}
      >
        <Img
          ml={6}
          nativeWidth={95}
          nativeHeight={90}
          alt="Document and magnifying glass"
          src={NothingFound}
        />
        <Text color="navyblue-100" fontWeight="bold" mt={2}>
          {title}
        </Text>
      </Flex>
    </Flex>
  );
};

export default NoResultsFound;
