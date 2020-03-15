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
import { Alert, Box, Card, Flex, Table } from 'pouncejs';
import ErrorBoundary from 'Components/ErrorBoundary';
import { Destination } from 'Generated/schema';
import { extractErrorMessage } from 'Helpers/utils';
import { useListDestinationsAndDefaults } from './graphql/listDestinationsAndDefaults.generated';
import columns from './columns';
import DestinationsPageSkeleton from './Skeleton';
import DestinationsPageEmptyDataFallback from './EmptyDataFallback';
import DestinationCreateButton from './CreateButton';

export interface ListDestinationsQueryData {
  destinations: Destination[];
}

const ListDestinations = () => {
  const { loading, error, data } = useListDestinationsAndDefaults({
    fetchPolicy: 'cache-and-network',
  });

  if (loading && !data) {
    return <DestinationsPageSkeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your available destinations"
        description={
          extractErrorMessage(error) ||
          'There was an error while attempting to list your Destinations'
        }
      />
    );
  }

  if (!data.destinations.length) {
    return <DestinationsPageEmptyDataFallback />;
  }

  return (
    <Box mb={6}>
      <Flex justifyContent="flex-end">
        <DestinationCreateButton />
      </Flex>
      <Card>
        <ErrorBoundary>
          <Table<Destination>
            items={data.destinations}
            getItemKey={item => item.outputId}
            columns={columns}
          />
        </ErrorBoundary>
      </Card>
    </Box>
  );
};

export default ListDestinations;
