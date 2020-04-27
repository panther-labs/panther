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
import { Box, Flex } from 'pouncejs';
import Navigation from 'Components/Navigation';
import Header from 'Components/Header';

const Layout: React.FC = ({ children }) => {
  return (
    <Flex minHeight="100%" bg="white">
      <Navigation />
      <Box as="main" minHeight={1} flex="1 0 auto" bg="grey50">
        <Box width={1214} mx="auto">
          <Header />
          <Box mt={6}>{children}</Box>
        </Box>
      </Box>
    </Flex>
  );
};

export default Layout;
