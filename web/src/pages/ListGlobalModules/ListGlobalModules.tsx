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
import TablePlaceholder from 'Components/TablePlaceholder';
import { Alert, Box, Button, Card, Flex, SimpleGrid } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import ErrorBoundary from 'Components/ErrorBoundary';
import { convertObjArrayValuesToCsv, encodeParams, extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import { useListGlobalModules } from './graphql/listGlobalModules.generated';
import EmptyDataFallback from './EmptyDataFallback';
import GlobalItem from './GlobalItem';

const ListGlobalModules = () => {
  const { loading, error, data } = useListGlobalModules({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: encodeParams(convertObjArrayValuesToCsv({}), ['nameContains']),
    },
  });

  if (loading && !data) {
    return (
      <Card p={9}>
        <TablePlaceholder />
      </Card>
    );
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

  if (!data.listGlobalModules) {
    return <EmptyDataFallback />;
  }

  return (
    <Box mb={6}>
      <Flex justify="flex-end">
        <Button
          size="large"
          variant="primary"
          mb={8}
          as={RRLink}
          to={urls.settings.globalModule.create()}
        >
          Create New
        </Button>
      </Flex>
      <ErrorBoundary>
        <SimpleGrid columns={2} spacing={3}>
          {data.listGlobalModules.globals.map(global => (
            <GlobalItem key={global.id} global={global} />
          ))}
        </SimpleGrid>
      </ErrorBoundary>
    </Box>
  );
};

export default withSEO({ title: 'Global Python Modules' })(ListGlobalModules);
