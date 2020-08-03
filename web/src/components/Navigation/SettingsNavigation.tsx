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
import { Box, Flex, Heading } from 'pouncejs';
import FadeInTrail from 'Components/utils/FadeInTrail';
import urls from 'Source/urls';
import NavLink from './NavLink';

const SettingsNavigation: React.FC = () => {
  return (
    <Box>
      <Heading size="x-small" fontWeight="bold" pt={7} pb={5}>
        SETTINGS
      </Heading>
      <Flex direction="column" as="ul">
        <FadeInTrail as="li">
          <NavLink icon="settings-alt" to={urls.settings.general()} label="General" />
          <NavLink icon="organization" to={urls.settings.users()} label="Users" />
          <NavLink icon="output" to={urls.settings.destinations()} label="Destinations" />
          <NavLink
            icon="wrench"
            to={urls.settings.globalPythonModules.list()}
            label="Global Modules"
          />
        </FadeInTrail>
      </Flex>
    </Box>
  );
};

export default React.memo(SettingsNavigation);
