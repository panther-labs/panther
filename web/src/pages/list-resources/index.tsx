/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { DEFAULT_LARGE_PAGE_SIZE, INTEGRATION_TYPES } from 'Source/constants';
import {
  Integration,
  ListResourcesInput,
  ListResourcesResponse,
  ListResourcesSortFieldsEnum,
  SortDirEnum,
} from 'Generated/schema';
import TablePaginationControls from 'Components/utils/table-pagination-controls';
import { useQuery, gql } from '@apollo/client';
import {
  convertObjArrayValuesToCsv,
  extendResourceWithIntegrationLabel,
  extractErrorMessage,
} from 'Helpers/utils';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isEmpty from 'lodash-es/isEmpty';
import ErrorBoundary from 'Components/error-boundary';
import ListResourcesActions from './subcomponents/list-resources-actions';
import ListResourcesTable from './subcomponents/list-resources-table';
import ListResourcesPageEmptyDataFallback from './empty-data-fallback';
import ListResourcesPageSkeleton from './skeleton';

const LIST_RESOURCES = gql`
  query ListResources($input: ListResourcesInput) {
    resources(input: $input) {
      resources {
        lastModified
        type
        integrationId
        complianceStatus
        id
      }
      paging {
        totalPages
        thisPage
        totalItems
      }
    }
    integrations(input: { integrationType: "${INTEGRATION_TYPES.AWS_INFRA}" }) {
        integrationLabel
        integrationId
    }
  }
`;

interface ApolloData {
  resources: ListResourcesResponse;
  integrations: Integration[];
}

interface ApolloVariables {
  input: ListResourcesInput;
}

const ListResources = () => {
  const {
    requestParams,
    updateRequestParamsAndResetPaging,
    updatePagingParams,
  } = useRequestParamsWithPagination<ListResourcesInput>();

  const { loading, error, data } = useQuery<ApolloData, ApolloVariables>(LIST_RESOURCES, {
    fetchPolicy: 'cache-and-network',
    variables: {
      input: convertObjArrayValuesToCsv(requestParams),
    },
  });

  if (loading && !data) {
    return <ListResourcesPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        mb={6}
        variant="error"
        title="Couldn't load your connected resources"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  const resourceItems = data.resources.resources;
  const integrationItems = data.integrations;
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
        <Card>
          <ListResourcesTable
            enumerationStartIndex={(pagingData.thisPage - 1) * DEFAULT_LARGE_PAGE_SIZE}
            items={enhancedResourceItems}
            onSort={updateRequestParamsAndResetPaging}
            sortBy={requestParams.sortBy || ListResourcesSortFieldsEnum.Id}
            sortDir={requestParams.sortDir || SortDirEnum.Ascending}
          />
        </Card>
      </ErrorBoundary>
      <Box my={6}>
        <TablePaginationControls
          page={pagingData.thisPage}
          totalPages={pagingData.totalPages}
          onPageChange={updatePagingParams}
        />
      </Box>
    </React.Fragment>
  );
};

export default ListResources;
