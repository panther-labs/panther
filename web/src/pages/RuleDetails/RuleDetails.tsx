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
import { Alert, Box, Flex, Card, TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import { extractErrorMessage } from 'Helpers/utils';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';

import withSEO from 'Hoc/withSEO';
import invert from 'lodash/invert';
import useUrlParams from 'Hooks/useUrlParams';
import ErrorBoundary from 'Components/ErrorBoundary';
import { AlertTypesEnum } from 'Generated/schema';
import RuleDetailsPageSkeleton from './Skeleton';
import ListRuleAlerts from './RuleAlertsListing';
import RuleDetailsInfo from './RuleDetailsInfo';
import RuleDetailsBanner from './RuleDetailsBanner';
import { useGetRuleDetails } from './graphql/getRuleDetails.generated';
import { useListAlertsForRule } from './graphql/listAlertsForRule.generated';

export interface RuleDetailsPageUrlParams {
  section?: 'details' | 'matches' | 'errors';
}

const sectionToTabIndex: Record<RuleDetailsPageUrlParams['section'], number> = {
  details: 0,
  matches: 1,
  errors: 2,
};

const tabIndexToSection = invert(sectionToTabIndex) as Record<
  number,
  RuleDetailsPageUrlParams['section']
>;

const RuleDetailsPage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { urlParams, setUrlParams } = useUrlParams<RuleDetailsPageUrlParams>();
  const { error, data, loading } = useGetRuleDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        id: match.params.id,
      },
    },
  });

  const { data: matchesData } = useListAlertsForRule({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        types: [AlertTypesEnum.Rule],
        ruleId: match.params.id,
        pageSize: DEFAULT_SMALL_PAGE_SIZE,
      },
    },
  });

  const { data: errorData } = useListAlertsForRule({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: {
        types: [AlertTypesEnum.RuleError],
        ruleId: match.params.id,
        pageSize: DEFAULT_SMALL_PAGE_SIZE,
      },
    },
  });

  if (loading && !data) {
    return <RuleDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6} data-testid={`rule-${match.params.id}`}>
        <Alert
          variant="error"
          title="Couldn't load rule"
          description={
            extractErrorMessage(error) ||
            " An unknown error occured and we couldn't load the rule details from the server"
          }
        />
      </Box>
    );
  }

  return (
    <Box as="article" mb={6}>
      <Flex direction="column" spacing={6}>
        <ErrorBoundary>
          <RuleDetailsBanner rule={data.rule} />
        </ErrorBoundary>
        <Card position="relative">
          <Tabs
            index={sectionToTabIndex[urlParams.section] || 0}
            onChange={index => setUrlParams({ section: tabIndexToSection[index] })}
          >
            <Box px={2}>
              <TabList>
                <BorderedTab>Details</BorderedTab>
                <BorderedTab>
                  <Box
                    data-testid="rule-matches"
                    opacity={matchesData?.alerts?.alertSummaries.length > 0 ? 1 : 0.5}
                  >
                    Rule Matches
                  </Box>
                </BorderedTab>
                <BorderedTab>
                  <Box
                    data-testid="rule-errors"
                    opacity={errorData?.alerts?.alertSummaries.length > 0 ? 1 : 0.5}
                  >
                    Rule Errors
                  </Box>
                </BorderedTab>
              </TabList>
              <BorderTabDivider />
              <TabPanels>
                <TabPanel data-testid="rule-details-tabpanel">
                  <RuleDetailsInfo rule={data.rule} />
                </TabPanel>
                <TabPanel data-testid="rule-matches-tabpanel" lazy unmountWhenInactive>
                  <ListRuleAlerts ruleId={match.params.id} type={AlertTypesEnum.Rule} />
                </TabPanel>
                <TabPanel data-testid="rule-errors-tabpanel" lazy unmountWhenInactive>
                  <ListRuleAlerts ruleId={match.params.id} type={AlertTypesEnum.RuleError} />
                </TabPanel>
              </TabPanels>
            </Box>
          </Tabs>
        </Card>
      </Flex>
    </Box>
  );
};

export default withSEO({ title: ({ match }) => match.params.id })(RuleDetailsPage);
