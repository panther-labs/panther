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
  buildPagingData,
  fireClickAndMouseEvents,
  render,
  waitFor,
} from 'test-utils';
import { GraphQLError } from 'graphql';
import { mockDeleteDataModel } from 'Components/modals/DeleteDataModelModal';
import ListDataModels from './ListDataModels';
import { mockListDataModels } from './graphql/listDataModels.generated';

describe('ListDataModels', () => {
  it('renders loading animation', () => {
    const { getByAriaLabel } = render(<ListDataModels />);

    expect(getByAriaLabel('Loading interface...')).toBeInTheDocument();
  });

  it('renders a fallback when no custom sources are present', async () => {
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

  it('renders a list of custom schemas', async () => {
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

  it('removes a custom schema upon successful deletion', async () => {
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
});
