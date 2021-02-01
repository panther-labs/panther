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
import urls from 'Source/urls';
import FadeInTrail from 'Components/utils/FadeInTrail';
import {
  useListDestinations,
  useListAvailableLogTypes,
  useListComplianceSourceNames,
} from 'Source/graphql/queries';
import NavLink from '../NavLink';

const LogAnalysisNavigation: React.FC = () => {
  // We expect that oftentimes the user will go need the available log types if the log analysis
  // menu was opened. This is because they are used everywhere, from the overview page, to the rule
  // creation page, to the list rules page. As an optimization, prefetch the list of the available
  // log types names as soon as the log analysis menu is opened. We also want it to be "passive" so
  // it should fail silently.
  // The same logic applies to available destinations
  useListAvailableLogTypes();
  useListDestinations();
  useListComplianceSourceNames();

  return (
    <Flex direction="column" as="ul" spacing={1}>
      <FadeInTrail as="li">
        <NavLink
          isSecondary
          icon="dashboard-alt"
          to={urls.logAnalysis.overview()}
          label="Overview"
        />
        <NavLink
          isSecondary
          icon="log-source"
          to={urls.logAnalysis.sources.list()}
          label="Sources"
        />
        <NavLink
          isSecondary
          icon="source-code"
          to={urls.logAnalysis.customLogs.list()}
          label="Custom Schemas"
        />
        <NavLink
          isSecondary
          icon="code-semi"
          to={urls.logAnalysis.dataModels.list()}
          label="Data Models"
        />
      </FadeInTrail>
    </Flex>
  );
};

export default React.memo(LogAnalysisNavigation);
