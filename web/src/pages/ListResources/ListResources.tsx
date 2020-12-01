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
import { Alert, Box, Card } from 'pouncejs';
import { ListResourcesInput, ListResourcesSortFieldsEnum, SortDirEnum } from 'Generated/schema';
import { TableControlsPagination } from 'Components/utils/TableControls';
import { extendResourceWithIntegrationLabel, extractErrorMessage } from 'Helpers/utils';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isEmpty from 'lodash/isEmpty';
import withSEO from 'Hoc/withSEO';
import ErrorBoundary from 'Components/ErrorBoundary';
import NoResultsFound from 'Components/NoResultsFound';
import ListResourcesActions from './ListResourcesActions';
import ListResourcesTable from './ListResourcesTable';
import ListResourcesPageEmptyDataFallback from './EmptyDataFallback';
import ListResourcesPageSkeleton from './Skeleton';
import { useListResources } from './graphql/listResources.generated';

const ListResources = () => {
  const {
    requestParams,
    updateRequestParamsAndResetPaging,
    updatePagingParams,
  } = useRequestParamsWithPagination<ListResourcesInput>();

  const { loading, data, error } = useListResources({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: requestParams,
    },
  });
  if (loading && !data) {
    return <ListResourcesPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load your connected resources"
          description={
            extractErrorMessage(error) ||
            'There was an error when performing your request, please contact support@runpanther.io'
          }
        />
      </Box>
    );
  }

  const resourceItems = data.resources.resources;
  const integrationItems = data.listComplianceIntegrations;
  const pagingData = data.resources.paging;

  if (!resourceItems.length && isEmpty(requestParams)) {
    return <ListResourcesPageEmptyDataFallback />;
  }

  // The items are enhanced with the key `integrationsLabel`
  const enhancedResourceItems = resourceItems.map(resource =>
    extendResourceWithIntegrationLabel(resource, integrationItems)
  );

  return (
    <React.Fragment>
      <ListResourcesActions />
      <ErrorBoundary>
        <Card as="section" px={8} py={4} position="relative">
          {enhancedResourceItems.length ? (
            <ListResourcesTable
              items={enhancedResourceItems}
              onSort={updateRequestParamsAndResetPaging}
              sortBy={requestParams.sortBy || ListResourcesSortFieldsEnum.Id}
              sortDir={requestParams.sortDir || SortDirEnum.Ascending}
            />
          ) : (
            <Box my={8}>
              <NoResultsFound />
            </Box>
          )}
        </Card>
      </ErrorBoundary>
      <Box my={6}>
        <TableControlsPagination
          page={pagingData.thisPage}
          totalPages={pagingData.totalPages}
          onPageChange={updatePagingParams}
        />
      </Box>
    </React.Fragment>
  );
};

export default withSEO({ title: 'Resources' })(ListResources);
