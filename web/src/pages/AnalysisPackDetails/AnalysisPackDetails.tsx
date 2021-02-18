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
import { compose } from 'Helpers/compose';
import useRouter from 'Hooks/useRouter';
import { Alert, Box, Flex, Card, SimpleGrid, TabList, TabPanel, TabPanels, Tabs } from 'pouncejs';
import { BorderedTab, BorderTabDivider } from 'Components/BorderedTab';
import { extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import invert from 'lodash/invert';
import useUrlParams from 'Hooks/useUrlParams';
import ErrorBoundary from 'Components/ErrorBoundary';
import RuleCard from 'Components/cards/RuleCard';
import { RuleSummary } from 'Source/graphql/fragments/RuleSummary.generated';
import { PolicySummary } from 'Source/graphql/fragments/PolicySummary.generated';
import EmptyDataFallback from 'Pages/AnalysisPackDetails/EmptyDataFallback';
import PolicyCard from 'Components/cards/PolicyCard';
import GlobalPythonModuleItem from 'Pages/ListGlobalPythonModules/GlobalPythonModuleItem/GlobalPythonModuleItem';
import DataModelCard from 'Pages/ListDataModels/DataModelCard';
import { useGetAnalysisPackDetails } from './graphql/getAnalysisPackDetails.generated';
import PackDetailsPageSkeleton from './Skeleton';
import AnalysisPackDetailsBanner from './AnalysisPackDetailsBanner';

export interface PackDetailsPageUrlParams {
  section?: 'rules' | 'policies' | 'helpers' | 'models';
}

const sectionToTabIndex: Record<PackDetailsPageUrlParams['section'], number> = {
  rules: 0,
  policies: 1,
  helpers: 2,
  models: 3,
};

const tabIndexToSection = invert(sectionToTabIndex) as Record<
  number,
  PackDetailsPageUrlParams['section']
>;

const PackDetailsPage: React.FC = () => {
  const { match } = useRouter<{ id: string }>();
  const { urlParams, setUrlParams } = useUrlParams<PackDetailsPageUrlParams>();
  const { error, data, loading } = useGetAnalysisPackDetails({
    fetchPolicy: 'cache-and-network',
    variables: {
      id: match.params.id,
    },
  });

  const [rules, policies, models, helpers] = React.useMemo(() => {
    const ruleData = (data?.getAnalysisPack?.enumeration?.detections.filter(
      d => d.analysisType === 'RULE'
    ) || []) as RuleSummary[];

    const policyData = (data?.getAnalysisPack?.enumeration?.detections.filter(
      d => d.analysisType === 'POLICY'
    ) || []) as PolicySummary[];

    const modelData = data?.getAnalysisPack?.enumeration?.models || [];

    const helperData = data?.getAnalysisPack?.enumeration?.globals || [];

    return [ruleData, policyData, modelData, helperData];
  }, [data]);

  if (loading) {
    return <PackDetailsPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6} data-testid={`pack-${match.params.id}`}>
        <Alert
          variant="error"
          title="Couldn't load Pack"
          description={
            extractErrorMessage(error) ||
            " An unknown error occured and we couldn't load the pack details from the server"
          }
        />
      </Box>
    );
  }

  return (
    <Box as="article" mb={6}>
      <Flex direction="column" spacing={6}>
        <ErrorBoundary>
          <AnalysisPackDetailsBanner pack={data.getAnalysisPack} />
        </ErrorBoundary>
        <Card position="relative">
          <Tabs
            index={sectionToTabIndex[urlParams.section] || 0}
            onChange={index => setUrlParams({ section: tabIndexToSection[index] })}
          >
            <Box px={2}>
              <TabList>
                <BorderedTab>
                  <Box data-testid="pack-rules" opacity={rules.length > 0 ? 1 : 0.5}>
                    Rules
                  </Box>
                </BorderedTab>
                <BorderedTab>
                  <Box data-testid="pack-policies" opacity={policies.length > 0 ? 1 : 0.5}>
                    Policies
                  </Box>
                </BorderedTab>
                <BorderedTab>
                  <Box data-testid="pack-helpers" opacity={helpers.length > 0 ? 1 : 0.5}>
                    Helpers
                  </Box>
                </BorderedTab>
                <BorderedTab>
                  <Box data-testid="pack-models" opacity={models.length > 0 ? 1 : 0.5}>
                    Data Models
                  </Box>
                </BorderedTab>
              </TabList>
              <BorderTabDivider />
              <TabPanels>
                <TabPanel data-testid="pack-rules-tabpanel" lazy unmountWhenInactive>
                  {rules.length ? (
                    <SimpleGrid spacing={4} p={6}>
                      {rules.map(rule => (
                        <RuleCard key={rule.id} rule={rule} />
                      ))}
                    </SimpleGrid>
                  ) : (
                    <EmptyDataFallback message="No Rules on pack" />
                  )}
                </TabPanel>
                <TabPanel data-testid="pack-policies-tabpanel" lazy unmountWhenInactive>
                  {policies.length ? (
                    <SimpleGrid spacing={4} p={6}>
                      {policies.map(policy => (
                        <PolicyCard key={policy.id} policy={policy} />
                      ))}
                    </SimpleGrid>
                  ) : (
                    <EmptyDataFallback message="No Policies on pack" />
                  )}
                </TabPanel>
                <TabPanel data-testid="pack-helpers-tabpanel" lazy unmountWhenInactive>
                  {helpers.length ? (
                    <SimpleGrid spacing={4} column={2} p={6}>
                      {helpers.map(helper => (
                        <GlobalPythonModuleItem key={helper.id} globalPythonModule={helper} />
                      ))}
                    </SimpleGrid>
                  ) : (
                    <EmptyDataFallback message="No Helpers on pack" />
                  )}
                </TabPanel>
                <TabPanel data-testid="pack-models-tabpanel" lazy unmountWhenInactive>
                  {models.length ? (
                    <SimpleGrid spacing={4} p={6}>
                      {models.map(model => (
                        <DataModelCard key={model.id} dataModel={model} />
                      ))}
                    </SimpleGrid>
                  ) : (
                    <EmptyDataFallback message="No Data Models on pack" />
                  )}
                </TabPanel>
              </TabPanels>
            </Box>
          </Tabs>
        </Card>
      </Flex>
    </Box>
  );
};

export default compose(
  withSEO({ title: ({ match }) => match.params.id }),
  React.memo
)(PackDetailsPage);
