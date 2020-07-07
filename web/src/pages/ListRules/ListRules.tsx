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
import { convertObjArrayValuesToCsv, extractErrorMessage, encodeParams } from 'Helpers/utils';
import { ListRulesInput, SortDirEnum, ListRulesSortFieldsEnum } from 'Generated/schema';
import { TableControlsPagination } from 'Components/utils/TableControls';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import isEmpty from 'lodash-es/isEmpty';
import ErrorBoundary from 'Components/ErrorBoundary';
import withSEO from 'Hoc/withSEO';
import ListRulesTable from './ListRulesTable';
import ListRulesActions from './ListRulesActions';
import ListRulesPageSkeleton from './Skeleton';
import ListRulesPageEmptyDataFallback from './EmptyDataFallback';
import { useListRules } from './graphql/listRules.generated';

const ListRules = () => {
  const {
    requestParams,
    updateRequestParamsAndResetPaging,
    updatePagingParams,
  } = useRequestParamsWithPagination<ListRulesInput>();

  const { loading, error, data } = useListRules({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: encodeParams(convertObjArrayValuesToCsv(requestParams), ['nameContains']),
    },
  });

  if (loading && !data) {
    return <ListRulesPageSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load your rules"
          description={
            extractErrorMessage(error) ||
            'There was an error when performing your request, please contact support@runpanther.io'
          }
        />
      </Box>
    );
  }

  // Get query results while protecting against exceptions
  const ruleItems = data.rules.rules;
  const pagingData = data.rules.paging;

  if (!ruleItems.length && isEmpty(requestParams)) {
    return <ListRulesPageEmptyDataFallback />;
  }
  //  Check how many active filters exist by checking how many columns keys exist in the URL
  return (
    <React.Fragment>
      <ListRulesActions />
      <ErrorBoundary>
        <Card as="section" px={8} py={4} position="relative">
          <ListRulesTable
            items={ruleItems}
            onSort={updateRequestParamsAndResetPaging}
            sortBy={requestParams.sortBy || ListRulesSortFieldsEnum.Id}
            sortDir={requestParams.sortDir || SortDirEnum.Ascending}
          />
        </Card>
      </ErrorBoundary>
      <Box my={5}>
        <TableControlsPagination
          page={pagingData.thisPage}
          totalPages={pagingData.totalPages}
          onPageChange={updatePagingParams}
        />
      </Box>
    </React.Fragment>
  );
};

export default withSEO({ title: 'Rules' })(ListRules);
