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
  fireEvent,
  render,
  waitMs,
  waitFor,
  buildDataModel,
  fireClickAndMouseEvents,
  buildListAvailableLogTypesResponse,
  buildPagingData,
} from 'test-utils';
import urls from 'Source/urls';
import { GraphQLError } from 'graphql';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { mockListDataModels } from 'Pages/ListDataModels';
import CreateDataModel from './CreateDataModel';
import { mockCreateDataModel } from './graphql/createDataModel.generated';

jest.mock('Helpers/analytics');

describe('CreateDataModel', () => {
  it('can create a data model successfully', async () => {
    const dataModel = buildDataModel();
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: buildListAvailableLogTypesResponse({ logTypes: ['AWS.ALB'] }),
        },
      }),
      mockListDataModels({
        variables: { input: {} },
        data: { listDataModels: { models: [], paging: buildPagingData() } },
      }),
      mockCreateDataModel({
        variables: {
          input: {
            displayName: 'test-name',
            id: 'test-id',
            logTypes: ['AWS.ALB'],
            enabled: true,
            mappings: [{ name: 'test-field-name', method: '', path: 'test-field-path' }],
            body: '',
          },
        },
        data: { addDataModel: dataModel },
      }),
    ];

    const {
      getByText,
      getByLabelText,
      getAllByLabelText,
      findByText,
      history,
    } = render(<CreateDataModel />, { mocks });

    fireEvent.change(getByLabelText('Display Name'), { target: { value: 'test-name' } });
    fireEvent.change(getByLabelText('ID'), { target: { value: 'test-id' } });
    fireEvent.change(getAllByLabelText('Log Type')[0], { target: { value: 'AWS.ALB' } });
    fireClickAndMouseEvents(await findByText('AWS.ALB'));

    fireEvent.change(getByLabelText('Name'), { target: { value: 'test-field-name' } });
    fireEvent.change(getByLabelText('Field Path'), { target: { value: 'test-field-path' } });

    // wait for validation to kick in
    await waitMs(1);
    fireEvent.click(getByText('Save'));

    await waitFor(() =>
      expect(history.location.pathname).toEqual(urls.logAnalysis.dataModels.list())
    );

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedDataModel,
      src: SrcEnum.DataModels,
    });
  });

  it('can handle errors', async () => {
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: buildListAvailableLogTypesResponse({ logTypes: ['AWS.ALB'] }),
        },
      }),
      mockCreateDataModel({
        variables: {
          input: {
            displayName: 'test-name',
            id: 'test-id',
            logTypes: ['AWS.ALB'],
            enabled: true,
            mappings: [{ name: 'test-field-name', method: '', path: 'test-field-path' }],
            body: '',
          },
        },
        data: null,
        errors: [new GraphQLError('Fake Error Message')],
      }),
    ];

    const { getByText, getByLabelText, getAllByLabelText, findByText } = render(
      <CreateDataModel />,
      { mocks }
    );

    fireEvent.change(getByLabelText('Display Name'), { target: { value: 'test-name' } });
    fireEvent.change(getByLabelText('ID'), { target: { value: 'test-id' } });
    fireEvent.change(getAllByLabelText('Log Type')[0], { target: { value: 'AWS.ALB' } });
    fireClickAndMouseEvents(await findByText('AWS.ALB'));

    fireEvent.change(getByLabelText('Name'), { target: { value: 'test-field-name' } });
    fireEvent.change(getByLabelText('Field Path'), { target: { value: 'test-field-path' } });

    // wait for validation to kick in
    await waitMs(1);
    fireEvent.click(getByText('Save'));

    expect(await findByText('Fake Error Message')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToAddDataModel,
      src: SrcEnum.DataModels,
    });
  });
});
