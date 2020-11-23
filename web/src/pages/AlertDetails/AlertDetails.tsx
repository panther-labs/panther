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
import useRouter from 'Hooks/useRouter';
import { Alert, Box, Card, Flex, TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import Skeleton from 'Pages/AlertDetails/Skeleton';
import AlertEvents from 'Pages/AlertDetails/AlertDetailsEvents';
import Page404 from 'Pages/404';
import withSEO from 'Hoc/withSEO';
import ErrorBoundary from 'Components/ErrorBoundary';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import { extractErrorMessage, shortenId } from 'Helpers/utils';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import invert from 'lodash/invert';
import useUrlParams from 'Hooks/useUrlParams';
import { useListDestinations } from 'Source/graphql/queries';
import { useAlertDetails } from './graphql/alertDetails.generated';
import { useRuleTeaser } from './graphql/ruleTeaser.generated';
import AlertDetailsBanner from './AlertDetailsBanner';
import AlertDetailsInfo from './AlertDetailsInfo';

interface AlertDetailsPageUrlParams {
  section?: 'details' | 'events';
}

const sectionToTabIndex: Record<AlertDetailsPageUrlParams['section'], number> = {
  details: 0,
  events: 1,
};

const tabIndexToSection = invert(sectionToTabIndex) as Record<
  number,
  AlertDetailsPageUrlParams['section']
>;

const AlertDetailsPage = () => {
  const { match } = useRouter<{ id: string }>();
  const { urlParams, updateUrlParams } = useUrlParams<AlertDetailsPageUrlParams>();

  const {
    data: alertData,
    loading: alertLoading,
    error: alertError,
    fetchMore,
    variables,
  } = useAlertDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        alertId: match.params.id,
        eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
      },
    },
  });

  const { data: ruleData, loading: ruleLoading } = useRuleTeaser({
    skip: !alertData,
    variables: {
      input: {
        id: alertData?.alert?.ruleId,
      },
    },
  });

  // FIXME: The destination information should come directly from GraphQL, by executing another
  //  query in the Front-end and using the results of both to calculate it.
  const { data: destinationData, loading: destinationLoading } = useListDestinations();

  const fetchMoreEvents = React.useCallback(() => {
    fetchMore({
      variables: {
        input: {
          ...variables.input,
          eventsExclusiveStartKey: alertData.alert.eventsLastEvaluatedKey,
        },
      },
      updateQuery: (previousResult, { fetchMoreResult }) => {
        return {
          ...previousResult,
          ...fetchMoreResult,
          alert: {
            ...previousResult.alert,
            ...fetchMoreResult.alert,
            events: [...previousResult.alert.events, ...fetchMoreResult.alert.events],
          },
        };
      },
    });
  }, [fetchMore, variables, alertData]);

  if (
    (alertLoading && !alertData) ||
    (ruleLoading && !ruleData) ||
    (destinationLoading && !destinationData)
  ) {
    return <Skeleton />;
  }

  if (alertError) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load alert"
          description={
            extractErrorMessage(alertError) ||
            "An unknown error occurred and we couldn't load the alert details from the server"
          }
        />
      </Box>
    );
  }

  if (!alertData.alert) {
    return <Page404 />;
  }

  return (
    <Box as="article">
      <Flex direction="column" spacing={6} my={6}>
        <AlertDetailsBanner alert={alertData.alert} />
        <Card position="relative">
          <Tabs
            index={sectionToTabIndex[urlParams.section] || 0}
            onChange={index => updateUrlParams({ section: tabIndexToSection[index] })}
          >
            <Box px={2}>
              <TabList>
                <BorderedTab>Details</BorderedTab>
                <BorderedTab>Events ({alertData.alert.eventsMatched})</BorderedTab>
              </TabList>
            </Box>
            <BorderTabDivider />
            <Box p={6}>
              <TabPanels>
                <TabPanel data-testid="alert-details-tabpanel">
                  <ErrorBoundary>
                    <AlertDetailsInfo alert={alertData.alert} rule={ruleData?.rule} />
                  </ErrorBoundary>
                </TabPanel>
                <TabPanel lazy data-testid="alert-events-tabpanel">
                  <ErrorBoundary>
                    <AlertEvents alert={alertData.alert} fetchMore={fetchMoreEvents} />
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

export default withSEO({ title: ({ match }) => `Alert #${shortenId(match.params.id)}` })(
  AlertDetailsPage
);
