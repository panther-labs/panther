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
import { Alert, Box, FadeIn } from 'pouncejs';
import withSEO from 'Hoc/withSEO';
import ErrorBoundary from 'Components/ErrorBoundary';
import { extractErrorMessage } from 'Helpers/utils';
import Panel from 'Components/Panel';
import LinkButton from 'Components/buttons/LinkButton';
import urls from 'Source/urls';
import { useListDestinationsAndDefaults } from './graphql/listDestinationsAndDefaults.generated';
import DestinationsPageSkeleton from './Skeleton';
import DestinationsPageEmptyDataFallback from './EmptyDataFallback';
import ListDestinationsCards from './ListDestinationsCards';

const ListDestinations = () => {
  const { loading, error, data } = useListDestinationsAndDefaults();

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
      <ErrorBoundary>
        <Panel
          title="Destinations"
          actions={
            <LinkButton to={urls.integrations.destinations.create()} icon="add">
              Add Destination
            </LinkButton>
          }
        >
          <FadeIn>
            <ListDestinationsCards destinations={data.destinations} />
          </FadeIn>
        </Panel>
      </ErrorBoundary>
    </Box>
  );
};

export default withSEO({ title: 'Destinations' })(ListDestinations);
