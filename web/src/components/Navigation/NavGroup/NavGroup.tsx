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

import { Box, AbstractButton, Icon, IconProps, Collapse } from 'pouncejs';
import React from 'react';

type NavGroupProps = {
  icon: IconProps['type'];
  label: string;
  active?: boolean;
  onSelect: () => void;
  children?: React.ReactNode;
};

const NavGroup: React.FC<NavGroupProps> = ({ icon, label, active, onSelect, children }) => {
  return (
    <Box
      fontSize="medium"
      borderRadius="small"
      backgroundColor={active ? 'navyblue-500' : 'transparent'}
    >
      <AbstractButton
        px={4}
        py={3}
        display="flex"
        onClick={onSelect}
        alignItems="center"
        width="100%"
        _hover={{
          color: 'gray-50',
          backgroundColor: 'navyblue-500',
        }}
      >
        <Icon type={icon} size="medium" mr={3} />
        <Box>{label}</Box>
        <Icon
          transition="transform 200ms cubic-bezier(0.0, 0, 0.2, 1) 80ms"
          transform={active ? 'rotate(180deg)' : 'rotate(0deg)'}
          type="chevron-down"
          size="medium"
          justifySelf="flex-end"
          ml="auto"
        />
      </AbstractButton>
      <Collapse open={active}>
        <Box px={2} pb={2}>
          {children}
        </Box>
      </Collapse>
    </Box>
  );
};

export default NavGroup;
