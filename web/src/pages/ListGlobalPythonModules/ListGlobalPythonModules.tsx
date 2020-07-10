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
import { Alert, Button, SimpleGrid } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import urls from 'Source/urls';
import ErrorBoundary from 'Components/ErrorBoundary';
import { convertObjArrayValuesToCsv, encodeParams, extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import Panel from 'Components/Panel';
import { useListGlobalPythonModules } from './graphql/listGlobalPythonModules.generated';
import EmptyDataFallback from './EmptyDataFallback';
import GlobalPythonModuleItem from './GlobalPythonModuleItem';
import Skeleton from './Skeleton';

const ListGlobalPythonModules = () => {
  const { loading, error, data } = useListGlobalPythonModules({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: encodeParams(convertObjArrayValuesToCsv({}), ['nameContains']),
    },
  });

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

  if (!data.listGlobalPythonModules) {
    return <EmptyDataFallback />;
  }

  return (
    <Panel
      title="Python Modules"
      actions={
        <Button as={RRLink} to={urls.settings.globalPythonModules.create()}>
          Create New
        </Button>
      }
    >
      <ErrorBoundary>
        <SimpleGrid columns={2} spacing={3}>
          {data.listGlobalPythonModules.globals.map(globalPythonModule => (
            <GlobalPythonModuleItem
              key={globalPythonModule.id}
              globalPythonModule={globalPythonModule}
            />
          ))}
        </SimpleGrid>
      </ErrorBoundary>
    </Panel>
  );
};

export default withSEO({ title: 'Global Python Modules' })(ListGlobalPythonModules);
