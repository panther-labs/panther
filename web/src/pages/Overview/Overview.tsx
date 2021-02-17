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
import { invert } from 'lodash';
import { Box, Tabs, TabPanels, TabList, TabPanel, Icon, Heading } from 'pouncejs';
import withSEO from 'Hoc/withSEO';
import useUrlParams from 'Hooks/useUrlParams';
import AlertsOverview from './AlertsOverview';
import CloudSecurityOverview from './CloudSecurityOverview';
import DataOverview from './DataOverview';
import OverviewTab from './OverviewTab';

export interface OverviewUrlParams {
  tab?: 'alerts' | 'cloudSecurity' | 'data';
}

const tabToIndex: Record<OverviewUrlParams['tab'], number> = {
  alerts: 0,
  cloudSecurity: 1,
  data: 2,
};

const indexToTab = invert(tabToIndex) as Record<number, OverviewUrlParams['tab']>;

const Overview: React.FC = () => {
  const {
    urlParams: { tab },
    setUrlParams,
  } = useUrlParams<OverviewUrlParams>();

  React.useLayoutEffect(() => {
    if (!tab) {
      setUrlParams({ tab: 'alerts' });
    }
  }, [tab, useUrlParams]);

  return (
    <Box mt={6}>
      <Tabs
        index={tabToIndex[tab] || 0}
        onChange={index => setUrlParams({ tab: indexToTab[index] })}
      >
        <TabList>
          <OverviewTab>
            <Icon type="alert-circle" />
            <Heading as="h4" size="x-small">
              Alerts
            </Heading>
          </OverviewTab>
          <OverviewTab>
            <Icon type="cloud-security" />
            <Heading as="h4" size="x-small">
              Cloud Security
            </Heading>
          </OverviewTab>
          <OverviewTab>
            <Icon type="data" />
            <Heading as="h4" size="x-small">
              Data
            </Heading>
          </OverviewTab>
        </TabList>
        <Box mt={6}>
          <TabPanels>
            <TabPanel lazy>
              <AlertsOverview />
            </TabPanel>
            <TabPanel lazy>
              <CloudSecurityOverview />
            </TabPanel>
            <TabPanel lazy>
              <DataOverview />
            </TabPanel>
          </TabPanels>
        </Box>
      </Tabs>
    </Box>
  );
};

export default withSEO({ title: 'Overview' })(Overview);
