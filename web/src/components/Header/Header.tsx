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
import Breadcrumbs from 'Components/Breadcrumbs';
import { Box, Flex } from 'pouncejs';
import useRouter from 'Hooks/useRouter';
import urls from 'Source/urls';

/** Array containing urls without header */
const excludedUrls = [urls.overview.home()];

const Header = () => {
  const {
    location: { pathname },
  } = useRouter();
  if (excludedUrls.includes(pathname)) {
    return null;
  }

  return (
    <Flex id="main-header" as="header" width={1} align="center" justify="space-between" py={6}>
      <Box py={14}>
        <Breadcrumbs />
      </Box>
    </Flex>
  );
};

export default Header;
