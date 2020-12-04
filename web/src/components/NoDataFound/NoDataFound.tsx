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
import { Heading, Flex, Img } from 'pouncejs';
import NoDataFoundIllustration from 'Assets/illustrations/charts.svg';

interface NoDataFoundProps {
  title?: string;
  children?: never;
}

const NoDataFound: React.FC<NoDataFoundProps> = ({ title = "You don't have any data" }) => {
  return (
    <Flex height="100%" direction="column" align="center" justify="center">
      <Img nativeWidth={80} nativeHeight={90} alt="Charts" src={NoDataFoundIllustration} />
      <Heading size="x-small" color="navyblue-100" mt={6}>
        {title}
      </Heading>
    </Flex>
  );
};

export default NoDataFound;
