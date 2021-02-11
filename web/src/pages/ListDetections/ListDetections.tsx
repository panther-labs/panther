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
import { Alert, Box, Card, Flex } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import { Detection, DetectionTypeEnum, ListDetectionsInput } from 'Generated/schema';
import { TableControlsPagination } from 'Components/utils/TableControls';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isEmpty from 'lodash/isEmpty';
import ErrorBoundary from 'Components/ErrorBoundary';
import NoResultsFound from 'Components/NoResultsFound';
import withSEO from 'Hoc/withSEO';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import Panel from 'Components/Panel';
import RuleCard from 'Components/cards/RuleCard';
import PolicyCard from 'Components/cards/PolicyCard';
import { RuleSummary } from 'Source/graphql/fragments/RuleSummary.generated';
import { useSelect, withSelectContext, SelectAllCheckbox } from 'Components/utils/SelectContext';
import { compose } from 'Helpers/compose';
import { PolicySummary } from 'Source/graphql/fragments/PolicySummary.generated';
import { DEFAULT_SMALL_PAGE_SIZE } from 'Source/constants';
import ListDetectionsPageSkeleton from './Skeleton';
import ListDetectionsPageEmptyDataFallback from './EmptyDataFallback';
import ListDetectionsActions from './ListDetectionsActions';
import { useListDetections } from './graphql/listDetections.generated';

const ListDetections = () => {
  useTrackPageView(PageViewEnum.ListDetections);

  const { checkIfSelected } = useSelect<Detection>();
  const { requestParams, updatePagingParams } = useRequestParamsWithPagination<
    ListDetectionsInput
  >();

  const { loading, error, data } = useListDetections({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: { ...requestParams, pageSize: DEFAULT_SMALL_PAGE_SIZE },
    },
  });

  if (loading && !data) {
    return <ListDetectionsPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load your detections"
          description={
            extractErrorMessage(error) ||
            'There was an error when performing your request, please contact support@runpanther.io'
          }
        />
      </Box>
    );
  }

  // Get query results while protecting against exceptions
  const detectionItems = data.detections.detections;
  const pagingData = data.detections.paging;

  if (!detectionItems.length && isEmpty(requestParams)) {
    return <ListDetectionsPageEmptyDataFallback />;
  }

  //  Check how many active filters exist by checking how many columns keys exist in the URL
  return (
    <ErrorBoundary>
      <Panel
        title={
          <Flex align="center" spacing={4}>
            <SelectAllCheckbox selectionItems={detectionItems} />
            <Box as="span">Detections</Box>
          </Flex>
        }
        actions={<ListDetectionsActions />}
      >
        <Card as="section" position="relative">
          <Box position="relative">
            <Flex direction="column" spacing={2}>
              {detectionItems.length ? (
                detectionItems.map(detection => {
                  switch (detection.analysisType) {
                    case DetectionTypeEnum.Rule:
                      return (
                        <RuleCard
                          key={detection.id}
                          rule={detection as RuleSummary}
                          selectionEnabled
                          isSelected={checkIfSelected(detection as Detection)}
                        />
                      );
                    case DetectionTypeEnum.Policy:
                      return (
                        <PolicyCard
                          selectionEnabled
                          policy={detection as PolicySummary}
                          key={detection.id}
                          isSelected={checkIfSelected(detection as Detection)}
                        />
                      );
                    default:
                      return null;
                  }
                })
              ) : (
                <Box my={8}>
                  <NoResultsFound />
                </Box>
              )}
            </Flex>
          </Box>
        </Card>
      </Panel>
      <Box my={5}>
        <TableControlsPagination
          page={pagingData.thisPage}
          totalPages={pagingData.totalPages}
          onPageChange={updatePagingParams}
        />
      </Box>
    </ErrorBoundary>
  );
};

export default compose(withSEO({ title: 'Detections' }), withSelectContext)(ListDetections);
