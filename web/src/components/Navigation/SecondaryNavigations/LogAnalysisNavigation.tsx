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
import urls from 'Source/urls';
import FadeInTrail from 'Components/utils/FadeInTrail';
import { AlertStatusesEnum } from 'Generated/schema';
import { useListDestinations, useListAvailableLogTypes } from 'Source/graphql/queries';
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

  return (
    <Box>
      <Heading size="x-small" fontWeight="bold" pt={4} pb={5} truncated>
        LOG ANALYSIS
      </Heading>
      <Flex direction="column" as="ul">
        <FadeInTrail as="li">
          <NavLink icon="dashboard-alt" to={urls.logAnalysis.overview()} label="Overview" />
          <NavLink
            icon="rule"
            to={`${urls.logAnalysis.rules.list()}?page=1&sortBy=lastModified&sortDir=descending`}
            label="Rules"
          />
          <NavLink
            icon="alert"
            to={`${urls.logAnalysis.alerts.list()}?status[]=${AlertStatusesEnum.Open}&status[]=${
              AlertStatusesEnum.Triaged
            }`}
            label="Alerts"
          />
          <NavLink icon="log-source" to={urls.logAnalysis.sources.list()} label="Sources" />
        </FadeInTrail>
      </Flex>
    </Box>
  );
};

export default React.memo(LogAnalysisNavigation);
