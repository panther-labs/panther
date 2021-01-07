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
  buildDataModelMapping,
} from 'test-utils';
import urls from 'Source/urls';
import { GraphQLError } from 'graphql';
import { Route } from 'react-router-dom';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import EditDataModel from './EditDataModel';
import { mockGetDataModel } from './graphql/getDataModel.generated';
import { mockUpdateDataModel } from './graphql/updateDataModel.generated';

jest.mock('Helpers/analytics');

describe('UpdateDataModel', () => {
  it('can create a data model successfully', async () => {
    const dataModel = buildDataModel({
      id: 'test',
      logTypes: ['AWS.ALB'],
      enabled: false,
      mappings: [buildDataModelMapping({ path: '' })],
      body: '',
    });

    const updatedDataModel = buildDataModel({
      id: 'test',
      logTypes: ['AWS.ECS'],
      enabled: true,
      displayName: 'Updated Name',
      mappings: [buildDataModelMapping({ name: 'updated-name', method: 'updated-method' })],
      body: 'def path(): return ""',
    });

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: buildListAvailableLogTypesResponse({
            logTypes: ['AWS.ALB', 'AWS.ECS'],
          }),
        },
      }),
      mockGetDataModel({
        variables: { id: dataModel.id },
        data: { getDataModel: dataModel },
      }),
      mockUpdateDataModel({
        variables: {
          input: updatedDataModel,
        },
        data: { updateDataModel: updatedDataModel },
      }),
    ];

    const { getByText, getByLabelText, getAllByLabelText, findByText, history } = render(
      <Route exact path={urls.logAnalysis.dataModels.edit(':id')}>
        <EditDataModel />
      </Route>,
      { mocks, initialRoute: urls.logAnalysis.dataModels.edit(dataModel.id) }
    );

    fireEvent.change(getByLabelText('Display Name'), { target: { value: 'test-name' } });
    fireEvent.change(getByLabelText('ID'), { target: { value: 'test-id' } });
    fireEvent.change(getAllByLabelText('Log Type')[0], { target: { value: 'AWS.ALB' } });
    fireClickAndMouseEvents(await findByText('AWS.ALB'));

    fireEvent.change(getByLabelText('Name'), { target: { value: 'test-field-name' } });
    fireEvent.change(getByLabelText('Field Path'), { target: { value: 'test-field-path' } });

    // wait for validation to kick in
    await waitMs(10);
    fireEvent.click(getByText('Save'));

    await waitFor(() =>
      expect(history.location.pathname).toEqual(urls.logAnalysis.dataModels.details(dataModel.id))
    );

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedDataModel,
      src: SrcEnum.DataModels,
    });
  });

  it('can handle errors', async () => {
    const dataModel = buildDataModel({
      id: 'test',
      logTypes: ['AWS.ALB'],
      enabled: false,
      mappings: [buildDataModelMapping({ path: '' })],
      body: '',
    });

    const updatedDataModel = buildDataModel({
      id: 'test',
      logTypes: ['AWS.ECS'],
      enabled: true,
      displayName: 'Updated Name',
      mappings: [buildDataModelMapping({ name: 'updated-name', method: 'updated-method' })],
      body: 'def path(): return ""',
    });

    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: buildListAvailableLogTypesResponse({
            logTypes: ['AWS.ALB', 'AWS.ECS'],
          }),
        },
      }),
      mockGetDataModel({
        variables: { id: dataModel.id },
        data: { getDataModel: dataModel },
      }),
      mockUpdateDataModel({
        variables: {
          input: updatedDataModel,
        },
        data: null,
        errors: [new GraphQLError('An error has occurred')],
      }),
    ];

    const { getByText, getByLabelText, getAllByLabelText, findByText } = render(
      <Route exact path={urls.logAnalysis.dataModels.edit(':id')}>
        <EditDataModel />
      </Route>,
      {
        mocks,
      }
    );

    fireEvent.change(getByLabelText('Display Name'), { target: { value: 'test-name' } });
    fireEvent.change(getByLabelText('ID'), { target: { value: 'test-id' } });
    fireEvent.change(getAllByLabelText('Log Type')[0], { target: { value: 'AWS.ALB' } });
    fireClickAndMouseEvents(await findByText('AWS.ALB'));

    fireEvent.change(getByLabelText('Name'), { target: { value: 'test-field-name' } });
    fireEvent.change(getByLabelText('Field Path'), { target: { value: 'test-field-path' } });

    // wait for validation to kick in
    await waitMs(10);
    fireEvent.click(getByText('Save'));

    expect(await findByText('Fake Error Message')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToAddDataModel,
      src: SrcEnum.DataModels,
    });
  });
});
