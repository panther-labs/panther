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
import { Flex, Icon, Text } from 'pouncejs';

interface FieldPolicyCheckProps {
  passing: boolean;
}

const FieldPolicyCheck: React.FC<FieldPolicyCheckProps> = ({ passing, children }) => {
  return (
    <Flex align="center">
      <Icon
        type={passing ? 'check-circle' : 'close-circle'}
        color={passing ? 'green-400' : 'navyblue-100'}
        size="medium"
        mr={2}
        aria-label={passing ? 'Check is passing' : 'Check is failing'}
      />
      <Text fontSize="small-medium" color={passing ? undefined : 'navyblue-100'}>
        {children}
      </Text>
    </Flex>
  );
};

export default FieldPolicyCheck;
