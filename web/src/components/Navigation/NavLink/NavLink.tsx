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

import { Box, Icon, IconProps } from 'pouncejs';
import React from 'react';
import useRouter from 'Hooks/useRouter';
import { addTrailingSlash, getPathnameFromURI } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';

type NavLinkProps = {
  icon: IconProps['type'];
  label: string;
  to: string;
  isSecondary?: boolean;
};

const NavLink: React.FC<NavLinkProps> = ({ icon, label, to, isSecondary }) => {
  const { location } = useRouter();
  const pathname = addTrailingSlash(location.pathname);
  const destination = addTrailingSlash(getPathnameFromURI(to));
  const isActive = pathname.startsWith(destination);

  const activeColor = isSecondary || isActive ? 'blue-400' : 'navyblue-500';
  const backgroundColor = isActive ? 'blue-400' : 'transparent';

  return (
    <Box as={RRLink} display="block" to={to} aria-current={isActive ? 'page' : undefined}>
      <Box
        borderRadius="small"
        color="gray-50"
        fontSize={isSecondary ? 'small-medium' : 'medium'}
        display="flex"
        alignItems="center"
        px={isSecondary ? 2 : 4}
        py={3}
        backgroundColor={backgroundColor}
        _hover={{
          backgroundColor: activeColor,
        }}
        _focus={{
          backgroundColor: activeColor,
        }}
        transition="background-color 200ms cubic-bezier(0.0, 0, 0.2, 1) 0ms"
        truncated
      >
        <Icon type={icon} size={isSecondary ? 'small' : 'medium'} mr={isSecondary ? 4 : 3} />
        <Box>{label}</Box>
      </Box>
    </Box>
  );
};

export default NavLink;
