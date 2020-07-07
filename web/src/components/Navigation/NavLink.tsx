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

import { Box, Icon, IconProps, PseudoBox } from 'pouncejs';
import React from 'react';
import useRouter from 'Hooks/useRouter';
import { Link as RRLink } from 'react-router-dom';

type NavLinkProps = {
  icon: IconProps['type'];
  label: string;
  to: string;
};

const NavLink: React.FC<NavLinkProps> = ({ icon, label, to }) => {
  const { location } = useRouter();

  const isActive = location.pathname.startsWith(to);
  return (
    <Box as={RRLink} display="block" to={to} my={1} aria-current={isActive ? 'page' : undefined}>
      <PseudoBox
        color="gray-50"
        fontSize="medium"
        fontWeight="medium"
        px={4}
        py={3}
        borderRadius="small"
        backgroundColor={isActive ? 'blue-600' : 'transparent'}
        _hover={{
          backgroundColor: isActive ? 'blue-600' : 'navyblue-700',
        }}
        _focus={{
          backgroundColor: isActive ? 'blue-600' : 'navyblue-700',
        }}
        transition="background-color 200ms cubic-bezier(0.0, 0, 0.2, 1) 0ms"
        mx={3}
        truncated
      >
        <Icon type={icon} size="small" mr={4} />
        {label}
      </PseudoBox>
    </Box>
  );
};

export default NavLink;
