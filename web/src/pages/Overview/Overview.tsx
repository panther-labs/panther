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
import { Flex, Tabs, TabPanels, TabList, TabPanel, Icon, Text } from 'pouncejs';
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
    <Flex>
      <Tabs index={tabToIndex[tab]} onChange={index => setUrlParams({ tab: indexToTab[index] })}>
        <TabList>
          <OverviewTab>
            <Icon type="alert-circle" />
            <Text>Alerts</Text>
          </OverviewTab>
          <OverviewTab>
            <Icon type="alert-circle" />
            <Text>Cloud Security</Text>
          </OverviewTab>
          <OverviewTab>
            <Icon type="alert-circle" />
            <Text>Data</Text>
          </OverviewTab>
        </TabList>
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
      </Tabs>
    </Flex>
  );
};

export default withSEO({ title: 'Overview' })(Overview);
