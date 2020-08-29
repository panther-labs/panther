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
import { Badge, Box, Flex, Icon, Img } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import { slugify } from 'Helpers/utils';

interface ItemCardProps {
  logo: string;
  title: string;
  disabled?: boolean;
  to: string;
}

const LogSourceCard: React.FC<ItemCardProps> = ({ logo, title, to, disabled }) => {
  const titleId = slugify(title);

  const content = (
    <Box
      aria-disabled={disabled}
      mb={5}
      border="1px solid"
      borderRadius="medium"
      borderColor="navyblue-300"
      transition="all 0.15s ease-in-out"
      _hover={{ backgroundColor: 'navyblue-500', borderColor: 'navyblue-500' }}
      _focus={{ backgroundColor: 'navyblue-500', borderColor: 'navyblue-500' }}
    >
      <Flex alignItems="center" py={3} px={6}>
        <Img
          aria-labelledby={titleId}
          src={logo}
          alt={title}
          objectFit="contain"
          nativeHeight={50}
          nativeWidth={50}
        />
        <Box id={titleId} px={4} py={3} textAlign="center">
          {title}
        </Box>
        <Box ml="auto">
          {disabled ? (
            <Badge color="violet-400" aria-labelledby={titleId}>
              AVAILABLE IN PANTHER ENTERPRISE
            </Badge>
          ) : (
            <Icon type="arrow-forward" />
          )}
        </Box>
      </Flex>
    </Box>
  );

  if (disabled) {
    return content;
  }

  return <RRLink to={to}>{content}</RRLink>;
};

export default LogSourceCard;
