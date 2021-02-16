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
import { Flex } from 'pouncejs';
import FadeInTrail from 'Components/utils/FadeInTrail';
import urls from 'Source/urls';
import NavLink from '../NavLink';

const SettingsNavigation: React.FC = () => {
  return (
    <Flex direction="column" as="ul">
      <FadeInTrail as="li">
        <NavLink isSecondary icon="settings-line" to={urls.settings.general()} label="General" />
        <NavLink isSecondary icon="organization" to={urls.settings.users()} label="Users" />
        <NavLink
          isSecondary
          icon="source-code"
          to={urls.settings.globalPythonModules.list()}
          label="Global Modules"
        />
        <NavLink
          isSecondary
          icon="multiple-upload"
          to={urls.settings.bulkUploader()}
          label="Bulk Uploader"
        />
      </FadeInTrail>
    </Flex>
  );
};

export default React.memo(SettingsNavigation);
