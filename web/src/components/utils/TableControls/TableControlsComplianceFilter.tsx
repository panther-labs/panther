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
import { AbstractButton, AbstractButtonProps, Box, theme } from 'pouncejs';

interface TableControlsComplianceFilterProps extends AbstractButtonProps {
  text: string;
  isActive: boolean;
  count?: number;
  countColor?: keyof typeof theme.colors;
}

const TableControlsComplianceFilter: React.FC<TableControlsComplianceFilterProps> = ({
  text,
  count,
  countColor,
  isActive,
  ...rest
}) => {
  return (
    <AbstractButton
      {...rest}
      py={2}
      px={3}
      color={isActive ? 'inherit' : 'gray-300'}
      borderRadius="medium"
      outline="none"
      backgroundColor={isActive ? 'navyblue-300' : 'transparent'}
      _hover={{
        backgroundColor: isActive ? 'navyblue-300' : 'navyblue-500',
      }}
      _focus={{
        backgroundColor: isActive ? 'navyblue-300' : 'navyblue-500',
      }}
    >
      {text}{' '}
      <Box fontSize="medium" color={countColor} as="span">
        {count}
      </Box>
    </AbstractButton>
  );
};

export default TableControlsComplianceFilter;
