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
import { extractErrorMessage } from 'Helpers/utils';
import { ListPoliciesInput, SortDirEnum, ListPoliciesSortFieldsEnum } from 'Generated/schema';
import { TableControlsPagination } from 'Components/utils/TableControls';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import ErrorBoundary from 'Components/ErrorBoundary';
import NoResultsFound from 'Components/NoResultsFound';
import isEmpty from 'lodash/isEmpty';
import withSEO from 'Hoc/withSEO';
import ListPoliciesTable from './ListPoliciesTable';
import ListPoliciesActions from './ListPoliciesActions';
import ListPoliciesPageSkeleton from './Skeleton';
import ListPoliciesPageEmptyDataFallback from './EmptyDataFallback';
import { useListPolicies } from './graphql/listPolicies.generated';

const ListPolicies = () => {
  const {
    requestParams,
    updateRequestParamsAndResetPaging,
    updatePagingParams,
  } = useRequestParamsWithPagination<ListPoliciesInput>();

  // FIXME: Apollo v3.x.x doesn't return previous data while waiting for new one. That means that
  // when we go to the "next page" a "loading interface" will be shown. Curreently, the existing
  // table is shown while the query is in flight
  // https://github.com/apollographql/apollo-client/issues/6603
  const { loading, error, data } = useListPolicies({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: requestParams,
    },
  });

  if (loading && !data) {
    return <ListPoliciesPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load your policies"
          description={
            extractErrorMessage(error) ||
            'There was an error when performing your request, please contact support@runpanther.io'
          }
        />
      </Box>
    );
  }

  const policyItems = data.policies.policies;
  const pagingData = data.policies.paging;

  if (!policyItems.length && isEmpty(requestParams)) {
    return <ListPoliciesPageEmptyDataFallback />;
  }

  return (
    <React.Fragment>
      <ListPoliciesActions />
      <ErrorBoundary>
        <Card as="section" px={8} py={4} position="relative">
          {policyItems.length ? (
            <ListPoliciesTable
              items={policyItems}
              onSort={updateRequestParamsAndResetPaging}
              sortBy={requestParams.sortBy || ListPoliciesSortFieldsEnum.Id}
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

export default withSEO({ title: 'Policies' })(ListPolicies);
