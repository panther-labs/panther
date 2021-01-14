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
import ErrorBoundary from 'Components/ErrorBoundary';
import { AlertDetailsRuleInfo } from 'Generated/schema';
import { AlertDetailsFull } from 'Source/graphql/fragments/AlertDetailsFull.generated';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { AlertDetails } from 'Pages/AlertDetails';
import invert from 'lodash/invert';
import useUrlParams from 'Hooks/useUrlParams';
import Skeleton from '../Skeleton';
import { useGetRuleSummary } from './graphql/getRuleSummary.generated';
import AlertDetailsBanner from './AlertDetailsBanner';
import AlertEvents from './AlertDetailsEvents';
import AlertDetailsInfo from './AlertDetailsInfo';

interface RuleAlertDetailsUrlParams {
  section?: 'details' | 'events';
}

const sectionToTabIndex: Record<RuleAlertDetailsUrlParams['section'], number> = {
  details: 0,
  events: 1,
};

const tabIndexToSection = invert(sectionToTabIndex) as Record<
  number,
  RuleAlertDetailsUrlParams['section']
>;

interface RuleAlertDetailsProps {
  alert: AlertDetailsFull;
  fetchMore: (params: any) => any;
}

const RuleAlertDetails: React.FC<RuleAlertDetailsProps> = ({ alert, fetchMore }) => {
  const { urlParams, updateUrlParams } = useUrlParams<RuleAlertDetailsUrlParams>();

  const alertDetectionInfo = alert.detection as AlertDetailsRuleInfo;

  const { data, loading } = useGetRuleSummary({
    variables: { input: { id: alertDetectionInfo.ruleId } },
  });

  const fetchMoreEvents = React.useCallback(() => {
    fetchMore({
      variables: {
        input: {
          alertId: alert.alertId,
          eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
          eventsExclusiveStartKey: alertDetectionInfo.eventsLastEvaluatedKey,
        },
      },
      updateQuery: (
        previousResult: AlertDetails,
        { fetchMoreResult }: { fetchMoreResult: AlertDetails }
      ): AlertDetails => {
        return {
          ...previousResult,
          ...fetchMoreResult,
          alert: {
            ...previousResult.alert,
            ...fetchMoreResult.alert,
            detection: {
              ...previousResult.alert.detection,
              ...fetchMoreResult.alert.detection,
              events: [
                ...(previousResult.alert.detection as AlertDetailsRuleInfo).events,
                ...(fetchMoreResult.alert.detection as AlertDetailsRuleInfo).events,
              ],
            },
          },
        };
      },
    });
  }, [fetchMore, alert]);

  if (loading && !data) {
    return <Skeleton />;
  }

  return (
    <Box as="article" mb={6}>
      <Flex direction="column" spacing={6}>
        <AlertDetailsBanner alert={alert} />
        <Card position="relative">
          <Tabs
            index={sectionToTabIndex[urlParams.section] || 0}
            onChange={index => updateUrlParams({ section: tabIndexToSection[index] })}
          >
            <Box px={2}>
              <TabList>
                <BorderedTab>Details</BorderedTab>
                <BorderedTab>Events ({alertDetectionInfo.eventsMatched})</BorderedTab>
              </TabList>
            </Box>
            <BorderTabDivider />
            <Box p={6}>
              <TabPanels>
                <TabPanel data-testid="alert-details-tabpanel">
                  <ErrorBoundary>
                    <AlertDetailsInfo alert={alert} rule={data?.rule} />
                  </ErrorBoundary>
                </TabPanel>
                <TabPanel lazy data-testid="alert-events-tabpanel">
                  <ErrorBoundary>
                    <AlertEvents alert={alert} fetchMore={fetchMoreEvents} />
                  </ErrorBoundary>
                </TabPanel>
              </TabPanels>
            </Box>
          </Tabs>
        </Card>
      </Flex>
    </Box>
  );
};

export default RuleAlertDetails;
