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
import { Box, Flex, Icon, Img, FadeIn } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import PantherEnterpriseLogo from 'Assets/panther-enterprise-minimal-logo.svg';
import { slugify } from 'Helpers/utils';
import useHover from 'Hooks/useHover';

interface ItemCardProps {
  logo: string;
  title: string;
  disabled?: boolean;
  to: string;
}

const LogSourceCard: React.FC<ItemCardProps> = ({ logo, title, to, disabled }) => {
  const { isHovering, handlers: hoverHandlers } = useHover();
  const titleId = slugify(title);

  const content = (
    <Box
      {...hoverHandlers}
      aria-disabled={disabled}
      border="1px solid"
      borderRadius="medium"
      transition="all 0.15s ease-in-out"
      backgroundColor={isHovering ? 'navyblue-500' : 'transparent'}
      borderColor={isHovering ? 'navyblue-500' : 'navyblue-300'}
      _focus={{ backgroundColor: 'navyblue-500', borderColor: 'navyblue-500' }}
    >
      <Flex alignItems="center" py={3} px={3}>
        <Img
          aria-labelledby={titleId}
          src={logo}
          alt={title}
          objectFit="contain"
          nativeHeight={26}
          nativeWidth={26}
        />
        <Box id={titleId} px={3} textAlign="left">
          {title}
        </Box>
        <Flex align="center" ml="auto">
          {disabled && (
            <Img
              nativeWidth={20}
              nativeHeight={20}
              alt="Panther Enterprise Logo"
              src={PantherEnterpriseLogo}
            />
          )}
          {isHovering && (
            <FadeIn from="left" offset={3}>
              <Icon type="arrow-forward" />
            </FadeIn>
          )}
        </Flex>
      </Flex>
    </Box>
  );

  if (disabled) {
    return content;
  }

  return <RRLink to={to}>{content}</RRLink>;
};

export default React.memo(LogSourceCard);
