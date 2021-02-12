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

/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Alert, Box, Card, Flex } from 'pouncejs';
import { extractErrorMessage } from 'Helpers/utils';
import { compose } from 'Helpers/compose';
import { ListPacksInput } from 'Generated/schema';
import NoResultsFound from 'Components/NoResultsFound';
import ErrorBoundary from 'Components/ErrorBoundary';
import withSEO from 'Hoc/withSEO';
import useTrackPageView from 'Hooks/useTrackPageView';
import { PageViewEnum } from 'Helpers/analytics';
import Panel from 'Components/Panel';
import { TableControlsPagination } from 'Components/utils/TableControls';
import useRequestParamsWithPagination from 'Hooks/useRequestParamsWithPagination';
import mockedData from 'Pages/ListPacks/mockedData';
import PackCard from 'Components/cards/PackCard';
import ListPacksSkeleton from './Skeleton';
import { buildListPacksResponse } from '../../../__tests__/__mocks__/builders.generated';

const ListPacks = () => {
  useTrackPageView(PageViewEnum.ListPacks);
  const { updatePagingParams } = useRequestParamsWithPagination<ListPacksInput>();

  // FIXME: Waiting for BE to implement this request
  // const { loading, error, data } = useListPacks({
  //   fetchPolicy: 'cache-and-network',
  //   variables: {
  //     input: { ...requestParams, pageSize: DEFAULT_SMALL_PAGE_SIZE },
  //   },
  // });
  const loading = false;
  const error = null;
  const data = { listPacks: buildListPacksResponse({ packs: mockedData.packs }) };

  if (loading && !data) {
    return <ListPacksSkeleton />;
  }

  if (error) {
    return (
      <Box mb={6}>
        <Alert
          variant="error"
          title="Couldn't load packs"
          description={
            extractErrorMessage(error) ||
            'There was an error when performing your request, please contact support@runpanther.io'
          }
        />
      </Box>
    );
  }

  // Get query results while protecting against exceptions
  const packItems = data?.listPacks.packs;
  const pagingData = data?.listPacks.paging;

  return (
    <ErrorBoundary>
      <Panel title="Packs">
        <Card as="section" position="relative">
          <Box position="relative">
            <Flex direction="column" spacing={2}>
              {packItems.length ? (
                packItems.map(pack => <PackCard key={pack.id} pack={pack} />)
              ) : (
                <Box my={8}>
                  <NoResultsFound title="No Packs found" />
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

export default compose(withSEO({ title: 'Packs' }), React.memo)(ListPacks);
