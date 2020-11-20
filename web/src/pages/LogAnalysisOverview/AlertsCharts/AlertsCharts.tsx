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
import { LongSeriesData, SingleValue } from 'Generated/schema';
import AlertSummary from 'Pages/LogAnalysisOverview/AlertSummary';
import AlertsBySeverity from 'Pages/LogAnalysisOverview/AlertsBySeverity/AlertsBySeverity';
import MostActiveRules from 'Pages/LogAnalysisOverview/MostActiveRules/MostActiveRules';

interface LogTypeChartsProps {
  totalAlertsDelta: SingleValue[];
  alertsBySeverity: LongSeriesData;
  alertsByRuleID: SingleValue[];
}

const AlertsCharts: React.FC<LogTypeChartsProps> = ({
  totalAlertsDelta,
  alertsBySeverity,
  alertsByRuleID,
}) => {
  return (
    <Card as="section">
      <Tabs>
        <Box position="relative" pl={2} pr={4}>
          <TabList>
            <BorderedTab>Real-Time Alerts</BorderedTab>
            <BorderedTab>Most Active Rules</BorderedTab>
          </TabList>
          <BorderTabDivider />
        </Box>
        <Box p={6}>
          <TabPanels>
            <TabPanel lazy>
              <Box height={272}>
                <Flex direction="row" width="100%" height="100%">
                  <AlertSummary data={totalAlertsDelta} />
                  <AlertsBySeverity alerts={alertsBySeverity} />
                </Flex>
              </Box>
            </TabPanel>
            <TabPanel lazy>
              <MostActiveRules alertsByRuleID={alertsByRuleID} />
            </TabPanel>
          </TabPanels>
        </Box>
      </Tabs>
    </Card>
  );
};

export default AlertsCharts;
