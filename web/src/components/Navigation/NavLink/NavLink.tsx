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
};

const NavLink: React.FC<NavLinkProps> = ({ icon, label, to }) => {
  const { location } = useRouter();
  const pathname = addTrailingSlash(location.pathname);
  const destination = addTrailingSlash(getPathnameFromURI(to));
  const isActive = pathname.startsWith(destination);

  return (
    <Box as={RRLink} display="block" to={to} my={1} aria-current={isActive ? 'page' : undefined}>
      <Box
        color="gray-50"
        fontSize="medium"
        fontWeight="medium"
        px={4}
        py={3}
        borderRadius="small"
        backgroundColor={isActive ? 'blue-400' : 'transparent'}
        _hover={{
          backgroundColor: isActive ? 'blue-400' : 'navyblue-500',
        }}
        _focus={{
          backgroundColor: isActive ? 'blue-400' : 'navyblue-500',
        }}
        transition="background-color 200ms cubic-bezier(0.0, 0, 0.2, 1) 0ms"
        truncated
      >
        <Icon type={icon} size="small" mr={4} />
        {label}
      </Box>
    </Box>
  );
};

export default NavLink;
