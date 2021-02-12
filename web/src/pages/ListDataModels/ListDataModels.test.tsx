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
import {
  buildDataModel,
  buildListDataModelsResponse,
  buildPagingData,
  fireClickAndMouseEvents,
  fireEvent,
  render,
  waitFor,
  waitMs,
  within,
} from 'test-utils';
import { GraphQLError } from 'graphql';
import { ListDataModelsSortFieldsEnum, SortDirEnum } from 'Generated/schema';
import { queryStringOptions } from 'Hooks/useUrlParams';
import queryString from 'query-string';
import { mockDeleteDataModel } from 'Components/modals/DeleteDataModelModal';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import ListDataModels from './ListDataModels';
import { mockListDataModels } from './graphql/listDataModels.generated';

// Mock debounce so it just executes the callback instantly
jest.mock('lodash/debounce', () => jest.fn(fn => fn));

const parseParams = (search: string) => queryString.parse(search, queryStringOptions);

describe('ListDataModels', () => {
  it('renders loading animation', () => {
    const { getAllByAriaLabel } = render(<ListDataModels />);

    const loadingBlocks = getAllByAriaLabel('Loading interface...');
    expect(loadingBlocks.length).toBeGreaterThan(1);
  });

  it('renders a fallback when no data models are present', async () => {
    const mocks = [
      mockListDataModels({
        variables: { input: {} },
        data: { listDataModels: { models: [], paging: buildPagingData() } },
      }),
    ];

    const { findByAltText, getByText } = render(<ListDataModels />, { mocks });

    expect(await findByAltText('Empty data illustration')).toBeInTheDocument();
    expect(getByText('Create a Data Model')).toBeInTheDocument();
  });

  it('renders an error box when an exception occurs', async () => {
    const mocks = [
      mockListDataModels({
        variables: { input: {} },
        data: null,
        errors: [new GraphQLError('Test Error')],
      }),
    ];

    const { findByText } = render(<ListDataModels />, { mocks });

    expect(await findByText('Test Error')).toBeInTheDocument();
  });

  it('renders a list of data models', async () => {
    const dataModels = [
      buildDataModel({ displayName: 'Data.Model.1', id: '1' }),
      buildDataModel({ displayName: 'Data.Model.2', id: '2' }),
    ];

    const mocks = [
      mockListDataModels({
        variables: { input: {} },
        data: { listDataModels: { models: dataModels, paging: buildPagingData() } },
      }),
    ];
    const { findByText } = render(<ListDataModels />, { mocks });

    expect(await findByText(dataModels[0].displayName)).toBeInTheDocument();
    expect(await findByText(dataModels[1].displayName)).toBeInTheDocument();
  });

  it('removes a data model upon successful deletion', async () => {
    const dataModels = [
      buildDataModel({ displayName: 'Data.Model.1', id: '1' }),
      buildDataModel({ displayName: 'Data.Model.2', id: '2' }),
    ];

    const dataModelToDelete = dataModels[0];
    const mocks = [
      mockListDataModels({
        variables: { input: {} },
        data: { listDataModels: { models: dataModels, paging: buildPagingData() } },
      }),
      mockDeleteDataModel({
        variables: {
          input: { dataModels: [{ id: dataModelToDelete.id }] },
        },
        data: { deleteDataModel: true },
      }),
    ];
    const { getByText, getAllByAriaLabel, findByText } = render(<ListDataModels />, { mocks });

    const deletionNode = await findByText(dataModelToDelete.displayName);
    expect(deletionNode).toBeInTheDocument();

    fireClickAndMouseEvents(getAllByAriaLabel('Toggle Options')[0]);
    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));
    await waitFor(() => {
      expect(deletionNode).not.toBeInTheDocument();
    });
  });

  it('shows an error upon unsuccessful deletion', async () => {
    const dataModels = [
      buildDataModel({ displayName: 'Data.Model.1', id: '1' }),
      buildDataModel({ displayName: 'Data.Model.2', id: '2' }),
    ];

    const dataModelToDelete = dataModels[0];
    const mocks = [
      mockListDataModels({
        variables: { input: {} },
        data: { listDataModels: { models: dataModels, paging: buildPagingData() } },
      }),
      mockDeleteDataModel({
        variables: {
          input: { dataModels: [{ id: dataModelToDelete.id }] },
        },
        data: null,
        errors: [new GraphQLError('Custom Error')],
      }),
    ];
    const { getByText, getAllByAriaLabel, findByText } = render(<ListDataModels />, { mocks });

    await findByText(dataModelToDelete.displayName);

    fireClickAndMouseEvents(getAllByAriaLabel('Toggle Options')[0]);
    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));

    expect(await findByText('Custom Error')).toBeInTheDocument();
  });

  it('can correctly boot from URL params', async () => {
    const mockedLogTypes = ['AWS.ALB', 'AWS.CloudTrail'];
    const initialParams =
      `?enabled=true` +
      `&logTypes[]=${mockedLogTypes[0]}` +
      `&logTypes[]=${mockedLogTypes[1]}` +
      `&nameContains=test` +
      `&sortBy=${ListDataModelsSortFieldsEnum.Id}` +
      `&sortDir=${SortDirEnum.Ascending}`;
    const dataModels = [
      buildDataModel({ displayName: 'test.Data.Model.1', id: '1', logTypes: [mockedLogTypes[0]] }),
      buildDataModel({ displayName: 'test.Data.Model.2', id: '2', logTypes: [mockedLogTypes[1]] }),
    ];
    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: mockedLogTypes,
          },
        },
      }),
      mockListDataModels({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: dataModels,
          }),
        },
      }),
    ];

    const { findByText, getByLabelText, getAllByLabelText, getByText, findByTestId } = render(
      <ListDataModels />,
      {
        initialRoute: `/${initialParams}`,
        mocks,
      }
    );

    // Await for API requests to resolve
    await findByText('test.Data.Model.1');

    // Verify filter values outside of Dropdown
    expect(getByLabelText('Filter Data Models by text')).toHaveValue('test');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Id (A-Z)');

    // Verify filter values inside the Dropdown
    fireClickAndMouseEvents(getByText('Filters (2)'));
    const withinDropdown = within(await findByTestId('dropdown-data-model-listing-filters'));
    expect(withinDropdown.getByText(mockedLogTypes[0])).toBeInTheDocument();
    expect(withinDropdown.getByText(mockedLogTypes[1])).toBeInTheDocument();
    expect(withinDropdown.getByPlaceholderText('Only show enabled data models?')).toHaveValue(
      'Yes'
    );
  });

  it('correctly applies & resets dropdown filters', async () => {
    const mockedLogTypes = ['AWS.ALB', 'AWS.CloudTrail'];
    const initialParams =
      `?nameContains=test` +
      `&sortBy=${ListDataModelsSortFieldsEnum.Id}` +
      `&sortDir=${SortDirEnum.Ascending}`;
    const dataModels = [
      buildDataModel({
        displayName: 'test.Data.Model.1',
        id: '1',
        logTypes: [mockedLogTypes[0]],
      }),
      buildDataModel({
        displayName: 'test.Data.Model.2',
        id: '2',
        logTypes: [mockedLogTypes[1]],
      }),
    ];
    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: mockedLogTypes,
          },
        },
      }),
      mockListDataModels({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: dataModels,
          }),
        },
      }),
      mockListDataModels({
        variables: {
          input: { ...parsedInitialParams, logTypes: [mockedLogTypes[0]], enabled: false },
        },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: [
              buildDataModel({
                displayName: 'test.Data.Model.3',
                id: '3',
                logTypes: [mockedLogTypes[0]],
                enabled: false,
              }),
            ],
          }),
        },
      }),
    ];

    const {
      findByText,
      getByLabelText,
      getAllByLabelText,
      getByText,
      findByTestId,
      history,
    } = render(<ListDataModels />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Await for API requests to resolve
    await findByText('test.Data.Model.1');
    // Open the Dropdown
    fireClickAndMouseEvents(getByText('Filters'));
    let withinDropdown = within(await findByTestId('dropdown-data-model-listing-filters'));

    // Modify all the filter values
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Log Types')[0]);
    fireClickAndMouseEvents(await withinDropdown.findByText(mockedLogTypes[0]));
    fireClickAndMouseEvents(withinDropdown.getAllByLabelText('Enabled')[0]);
    fireClickAndMouseEvents(withinDropdown.getByText('No'));

    // Expect nothing to have changed until "Apply is pressed"
    expect(parseParams(history.location.search)).toEqual(parseParams(initialParams));

    // Apply the new values of the dropdown filters
    fireClickAndMouseEvents(withinDropdown.getByText('Apply Filters'));

    // Wait for side-effects to apply
    await waitMs(1);

    // Expect URL to have changed to mirror the filter updates
    const updatedParams = `${initialParams}&enabled=false&logTypes[]=${mockedLogTypes[0]}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));

    // Await for the new API request to resolve
    await findByText('test.Data.Model.3');

    // Expect the rest of the filters to be intact (to not have changed in any way)
    expect(getByLabelText('Filter Data Models by text')).toHaveValue('test');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Id (A-Z)');

    // Open the Dropdown (again)
    fireClickAndMouseEvents(getByText('Filters (2)'));
    withinDropdown = within(await findByTestId('dropdown-data-model-listing-filters'));

    // Clear all the filter values
    fireClickAndMouseEvents(withinDropdown.getByText('Clear Filters'));

    // Verify that they are cleared
    expect(withinDropdown.queryByText(mockedLogTypes[0])).toBeFalsy();
    expect(withinDropdown.getAllByLabelText('Enabled')[0]).toHaveValue('');

    // Expect the URL to not have changed until "Apply Filters" is clicked
    expect(parseParams(history.location.search)).toEqual(parseParams(updatedParams));

    // Apply the changes from the "Clear Filters" button
    fireClickAndMouseEvents(withinDropdown.getByText('Apply Filters'));

    // Wait for side-effects to apply
    await waitMs(1);

    // Expect the URL to reset to its original values
    expect(parseParams(history.location.search)).toEqual(parseParams(initialParams));

    // Expect the rest of the filters to STILL be intact (to not have changed in any way)
    expect(getByLabelText('Filter Data Models by text')).toHaveValue('test');
    expect(getAllByLabelText('Sort By')[0]).toHaveValue('Id (A-Z)');
  });

  it('correctly updates filters & sorts on every change outside of the dropdown', async () => {
    const mockedLogType = 'AWS.ALB';
    const initialParams = `?enabled=true&logTypes[]=${mockedLogType}`;

    const dataModels = [
      buildDataModel({ displayName: 'Data.Model.1', id: '1', logTypes: [mockedLogType] }),
      buildDataModel({ displayName: 'Data.Model.2', id: '2', logTypes: [mockedLogType] }),
    ];
    const parsedInitialParams = parseParams(initialParams);
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [mockedLogType],
          },
        },
      }),
      mockListDataModels({
        variables: {
          input: parsedInitialParams,
        },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: dataModels,
          }),
        },
      }),
      mockListDataModels({
        variables: {
          input: {
            ...parsedInitialParams,
            sortBy: ListDataModelsSortFieldsEnum.LastModified,
            sortDir: SortDirEnum.Descending,
            nameContains: 'test',
          },
        },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: [
              buildDataModel({
                displayName: 'sorted.test.Data.Model',
                id: '1',
              }),
            ],
          }),
        },
      }),
      mockListDataModels({
        variables: {
          input: {
            ...parsedInitialParams,
            nameContains: 'test',
          },
        },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: [
              buildDataModel({
                displayName: 'test.Data.Model',
                id: '1',
              }),
            ],
          }),
        },
      }),
    ];

    const {
      findByText,
      getByLabelText,
      getAllByLabelText,
      getByText,
      findByTestId,
      history,
    } = render(<ListDataModels />, {
      initialRoute: `/${initialParams}`,
      mocks,
    });

    // Await for API requests to resolve
    await findByText('Data.Model.1');

    // Expect the text filter to be empty by default
    const textFilter = getByLabelText('Filter Data Models by text');
    expect(textFilter).toHaveValue('');

    // Change it to something
    fireEvent.change(textFilter, { target: { value: 'test' } });

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const paramsWithTextFilter = `${initialParams}&nameContains=test`;
    expect(parseParams(history.location.search)).toEqual(parseParams(paramsWithTextFilter));

    // Expect the API request to have fired and a new data model to have returned (verifies API execution)
    await findByText('test.Data.Model');

    /* ****************** */

    // Expect the sort dropdown to be empty by default
    const sortFilter = getAllByLabelText('Sort By')[0];
    expect(sortFilter).toHaveValue('');

    // Change its value
    fireClickAndMouseEvents(sortFilter);
    fireClickAndMouseEvents(await findByText('Most Recent'));

    // Give a second for the side-effects to kick in
    await waitMs(1);

    // Expect the URL to be updated
    const paramsWithSortingAndTextFilter = `${paramsWithTextFilter}&sortBy=${ListDataModelsSortFieldsEnum.LastModified}&sortDir=${SortDirEnum.Descending}`;
    expect(parseParams(history.location.search)).toEqual(parseParams(paramsWithSortingAndTextFilter)); // prettier-ignore

    // Expect the API request to have fired and a new data model to have returned (verifies API execution)
    await findByText('sorted.test.Data.Model');

    // Verify that the filters inside the Dropdown are left intact
    fireClickAndMouseEvents(getByText('Filters (2)'));
    const withinDropdown = within(await findByTestId('dropdown-data-model-listing-filters'));
    expect(withinDropdown.getByText(mockedLogType)).toBeTruthy();
    expect(withinDropdown.getAllByLabelText('Enabled')[0]).toHaveValue('Yes');
  });

  it('can select and delete multiple data models', async () => {
    const dataModels = [
      buildDataModel({ displayName: 'Data.Model.1', id: '1' }),
      buildDataModel({ displayName: 'Data.Model.2', id: '2' }),
      buildDataModel({ displayName: 'Data.Model.3', id: '3' }),
    ];
    const dataModelsToDelete = [dataModels[0], dataModels[1]];

    const mocks = [
      mockListDataModels({
        variables: { input: {} },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: dataModels,
          }),
        },
      }),
      mockDeleteDataModel({
        variables: {
          input: { dataModels: dataModelsToDelete.map(m => ({ id: m.id })) },
        },
        data: { deleteDataModel: true },
      }),
    ];

    const { getByText, findByAriaLabel, getAllByAriaLabel, getByAriaLabel, queryByText } = render(
      <ListDataModels />,
      {
        mocks,
      }
    );

    // Check that select all checkbox is present
    expect(await findByAriaLabel('select all')).toBeInTheDocument();

    // Check that data models and checkboxes are rendered
    dataModels.forEach(dm => {
      expect(getByText(dm.displayName)).toBeInTheDocument();
    });
    expect(getAllByAriaLabel(`select item`)).toHaveLength(dataModels.length);

    // Single select all 3 Data Models
    getAllByAriaLabel(`select item`).forEach(dm => fireClickAndMouseEvents(dm));

    // Deselect third data model
    const checkedCheckboxForDataModel = getAllByAriaLabel(`unselect item`)[2];
    fireClickAndMouseEvents(checkedCheckboxForDataModel);
    expect(getByText('2 Selected')).toBeInTheDocument();
    expect(getAllByAriaLabel(`unselect item`)).toHaveLength(2);

    const massDeleteButton = getByAriaLabel('Delete selected Data Models');

    // Mass delete the selected data models
    fireClickAndMouseEvents(massDeleteButton);

    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));

    await waitMs(1);
    dataModelsToDelete.forEach(dm => expect(queryByText(dm.displayName)).not.toBeInTheDocument());
  });

  it('can select and delete all data models', async () => {
    const dataModels = [
      buildDataModel({ displayName: 'Data.Model.1', id: '1' }),
      buildDataModel({ displayName: 'Data.Model.2', id: '2' }),
      buildDataModel({ displayName: 'Data.Model.3', id: '3' }),
    ];

    const mocks = [
      mockListDataModels({
        variables: { input: {} },
        data: {
          listDataModels: buildListDataModelsResponse({
            models: dataModels,
          }),
        },
      }),
      mockDeleteDataModel({
        variables: {
          input: { dataModels: dataModels.map(m => ({ id: m.id })) },
        },
        data: { deleteDataModel: true },
      }),
    ];

    const { getByText, findByAriaLabel, getAllByAriaLabel, getByAriaLabel, queryByText } = render(
      <ListDataModels />,
      {
        mocks,
      }
    );

    // Check that select all checkbox is present
    const selectAll = await findByAriaLabel('select all');

    // Check that data models and checkboxes are rendered
    dataModels.forEach(dm => {
      expect(getByText(dm.displayName)).toBeInTheDocument();
    });
    expect(getAllByAriaLabel(`select item`)).toHaveLength(dataModels.length);

    // Select all data models
    fireClickAndMouseEvents(selectAll);
    expect(getByText('3 Selected')).toBeInTheDocument();

    // Check that all data models are selected
    expect(getAllByAriaLabel(`unselect item`)).toHaveLength(dataModels.length);

    const massDeleteButton = getByAriaLabel('Delete selected Data Models');

    // Mass delete the selected data models
    fireClickAndMouseEvents(massDeleteButton);

    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));

    await waitMs(1);
    dataModels.forEach(dm => expect(queryByText(dm.displayName)).not.toBeInTheDocument());
  });
});
