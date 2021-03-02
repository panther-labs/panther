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
import { Alert, Box, Flex } from 'pouncejs';
import Panel from 'Components/Panel';
import ErrorBoundary from 'Components/ErrorBoundary';
import { SelectAllCheckbox, withSelectContext } from 'Components/utils/SelectContext';
import { extractErrorMessage } from 'Helpers/utils';
import withSEO from 'Hoc/withSEO';
import useTrackPageView from 'Hooks/useTrackPageView';
import useRequestParamsWithoutPagination from 'Hooks/useRequestParamsWithoutPagination';
import { DataModel, ListDataModelsInput } from 'Generated/schema';
import { PageViewEnum } from 'Helpers/analytics';
import { compose } from 'Helpers/compose';
import EmptyDataFallback from './EmptyDataFallback';
import { useListDataModels } from './graphql/listDataModels.generated';
import DataModelCard from './DataModelCard';
import ListDataModelsSkeleton from './Skeleton';
import ListDataModelActions from './ListDataModelActions';

const ListDataModels = () => {
  useTrackPageView(PageViewEnum.ListDataModels);

  const { requestParams } = useRequestParamsWithoutPagination<ListDataModelsInput>();

  const { loading, error, data } = useListDataModels({
    fetchPolicy: 'cache-and-network',
    variables: {
      input: requestParams,
    },
  });
  const dataModels = data?.listDataModels?.models || [];

  if (loading && !data) {
    return <ListDataModelsSkeleton />;
  }

  return (
    <Box mb={6}>
      <ErrorBoundary>
        <Panel
          title={
            <Flex align="center" spacing={2} ml={4}>
              {dataModels.length > 0 && <SelectAllCheckbox selectionItems={dataModels} />}
              <Box as="span">Data Models</Box>
            </Flex>
          }
          actions={<ListDataModelActions />}
        >
          {error && (
            <Alert
              variant="error"
              title="Couldn't load your data models"
              description={
                extractErrorMessage(error) ||
                'There was an error while attempting to list your data models'
              }
            />
          )}
          {dataModels.length > 0 ? (
            <Flex direction="column" spacing={2}>
              {dataModels.map(dataModel => (
                <DataModelCard key={dataModel.id} dataModel={dataModel} selectionEnabled />
              ))}
            </Flex>
          ) : (
            <EmptyDataFallback />
          )}
        </Panel>
      </ErrorBoundary>
    </Box>
  );
};

export default compose(
  withSEO({ title: 'Data Models' }),
  withSelectContext({ getItemKey: (item: DataModel) => item.id })
)(ListDataModels);
