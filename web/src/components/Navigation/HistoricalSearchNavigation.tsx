/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { Box, Flex, Heading } from 'pouncejs';
import { useListLogDatabases } from 'Pages/SQLShell';
import urls from 'Source/urls';
import NavLink from './NavLink';

const HistoricalSearchNavigation: React.FC = () => {
  // We expect that oftentimes the user will go to the historical data if the historical search
  // menu was opened.
  //
  // As an optimization, prefetch a list of database names as soon as the historical search menu
  // is opened. This will make the related lambda hot (if it was cold) and will minimize the
  //  perceived delay from the user's standpoint
  useListLogDatabases();

  return (
    <Box>
      <Heading size="medium" textAlign="center" mt={10} mb={5}>
        <b>HISTORICAL SEARCH</b>
      </Heading>
      <Flex direction="column" as="ul">
        <Flex as="li">
          <NavLink icon="search" to={urls.historicalSearch.sqlShell()} label="SQL Shell" />
        </Flex>
      </Flex>
    </Box>
  );
};

export default HistoricalSearchNavigation;
