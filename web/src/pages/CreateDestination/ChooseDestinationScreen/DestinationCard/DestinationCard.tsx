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

import * as React from 'react';
import { Box, AbstractButton, Img, Flex } from 'pouncejs';

interface DestinationCardProps {
  logo: string;
  title: string;
  onClick?: () => void;
}

const DestinationCard: React.FunctionComponent<DestinationCardProps> = ({
  logo,
  title,
  onClick,
}) => (
  <AbstractButton
    p={3}
    width={1}
    onClick={onClick}
    outline="none"
    border="1px solid"
    borderRadius="medium"
    borderColor="navyblue-300"
    transition="all 0.15s ease-in-out"
    _hover={{ backgroundColor: 'navyblue-500', borderColor: 'navyblue-500' }}
    _focus={{ backgroundColor: 'navyblue-500', borderColor: 'navyblue-500' }}
  >
    <Flex align="center">
      <Img
        aria-labelledby={title}
        src={logo}
        alt={title}
        objectFit="contain"
        nativeWidth={30}
        nativeHeight={30}
        mr={2}
      />
      <Box id={title} as="span">
        {title}
      </Box>
    </Flex>
  </AbstractButton>
);

export default DestinationCard;
