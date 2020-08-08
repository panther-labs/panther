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
import NavLink from '../NavLink';

const LogAnalysisNavigation: React.FC = () => {
  return (
    <Box>
      <Heading size="x-small" fontWeight="bold" pt={4} pb={5} truncated>
        LOG ANALYSIS
      </Heading>
      <Flex direction="column" as="ul">
        <FadeInTrail as="li">
          <NavLink icon="dashboard-alt" to={urls.logAnalysis.overview()} label="Overview" />
          <NavLink icon="rule" to={urls.logAnalysis.rules.list()} label="Rules" />
          <NavLink icon="alert" to={urls.logAnalysis.alerts.list()} label="Alerts" />
          <NavLink icon="log-source" to={urls.logAnalysis.sources.list()} label="Sources" />
        </FadeInTrail>
      </Flex>
    </Box>
  );
};

export default React.memo(LogAnalysisNavigation);
