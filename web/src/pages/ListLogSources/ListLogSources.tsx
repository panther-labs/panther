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
import { Alert, Box, Button } from 'pouncejs';
import Panel from 'Components/Panel';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import ErrorBoundary from 'Components/ErrorBoundary';
import { extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import { useListLogSources } from './graphql/listLogSources.generated';
import EmptyDataFallback from './EmptyDataFallback';
import Skeleton from './Skeleton';
import ListDestinationsCards from './ListLogSourceCards';

const ListLogSources = () => {
  const { loading, error, data } = useListLogSources();

  if (loading && !data) {
    return <Skeleton />;
  }

  if (error) {
    return (
      <Alert
        variant="error"
        title="Couldn't load your sources"
        description={
          extractErrorMessage(error) ||
          'There was an error when performing your request, please contact support@runpanther.io'
        }
      />
    );
  }

  if (!data.listLogIntegrations.length) {
    return <EmptyDataFallback />;
  }

  return (
    <Box mb={6}>
      <Panel
        title="Log Sources"
        actions={
          <Button icon="add" as={RRLink} to={urls.logAnalysis.sources.create()}>
            Add Source
          </Button>
        }
      >
        <ErrorBoundary>
          <ListDestinationsCards sources={data.listLogIntegrations} />
        </ErrorBoundary>
      </Panel>
    </Box>
  );
};

export default withSEO({ title: 'Log Analysis Sources' })(ListLogSources);
