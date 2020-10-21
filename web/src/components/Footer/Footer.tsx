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
import ReactDOM from 'react-dom';
import { Box, Flex } from 'pouncejs';

const Footer: React.FC = ({ children }) => {
  return ReactDOM.createPortal(
    <Box bg="navyblue-500">
      <Flex width={1214} mx="auto" minHeight="100%" direction="column" py={6}>
        {children}
      </Flex>
    </Box>,
    document.getElementById('footer')
  );
};

export default Footer;
