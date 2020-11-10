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
import { Box, Card, Flex, TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import AlertCard from 'Components/cards/AlertCard';
import NoResultsFound from 'Components/NoResultsFound';
import { AlertSummaryFull } from 'Source/graphql/fragments/AlertSummaryFull.generated';

interface AlertsSectionProps {
  topAlerts: AlertSummaryFull[];
  recentAlerts: AlertSummaryFull[];
}

const AlertsSection: React.FC<AlertsSectionProps> = ({ topAlerts, recentAlerts }) => {
  return (
    <Card as="section">
      <Tabs>
        <Box position="relative" pl={2} pr={4}>
          <TabList>
            <BorderedTab>Recent Alerts ({recentAlerts.length})</BorderedTab>
            <BorderedTab>High Severity Alerts ({topAlerts.length})</BorderedTab>
          </TabList>
          <BorderTabDivider />
        </Box>
        <Box p={6}>
          <TabPanels>
            <TabPanel lazy>
              <Flex direction="column" spacing={2}>
                {recentAlerts.length ? (
                  recentAlerts.map(alert => <AlertCard key={alert.alertId} alert={alert} />)
                ) : (
                  <Box my={6}>
                    <NoResultsFound />
                  </Box>
                )}
              </Flex>
            </TabPanel>
            <TabPanel lazy>
              <Flex direction="column" spacing={2}>
                {topAlerts.length ? (
                  topAlerts.map(alert => <AlertCard key={alert.alertId} alert={alert} />)
                ) : (
                  <Box my={6}>
                    <NoResultsFound />
                  </Box>
                )}
              </Flex>
            </TabPanel>
          </TabPanels>
        </Box>
      </Tabs>
    </Card>
  );
};

export default AlertsSection;
