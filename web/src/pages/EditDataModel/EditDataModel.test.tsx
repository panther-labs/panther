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
import omit from 'lodash/omit';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import EditDataModel from './EditDataModel';
import { mockGetDataModel } from './graphql/getDataModel.generated';
import { mockUpdateDataModel } from './graphql/updateDataModel.generated';

jest.mock('Helpers/analytics');
jest.mock('lodash/debounce', () => jest.fn(fn => fn));

describe('UpdateDataModel', () => {
  it('can create a data model successfully', async () => {
    const dataModel = buildDataModel({
      id: 'test',
      displayName: 'test',
      logTypes: ['AWS.ALB'],
      enabled: false,
      mappings: [buildDataModelMapping({ name: 'test-name', method: 'test-method', path: '' })],
      body: '',
    });

    const updatedDataModel = buildDataModel({
      id: 'test',
      displayName: 'Updated Name',
      logTypes: ['AWS.ECS'],
      enabled: true,
      mappings: [
        buildDataModelMapping({ name: 'updated-name', method: 'updated-method', path: '' }),
      ],
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
          input: {
            displayName: updatedDataModel.displayName,
            id: updatedDataModel.id,
            logTypes: updatedDataModel.logTypes,
            enabled: updatedDataModel.enabled,
            mappings: updatedDataModel.mappings.map(m => omit(m, '__typename')),
            body: updatedDataModel.body,
          },
        },
        data: { updateDataModel: updatedDataModel },
      }),
    ];

    const {
      getByText,
      getByLabelText,
      getAllByLabelText,
      findByText,
      getByAriaLabel,
      getByPlaceholderText,
    } = render(
      <Route exact path={urls.logAnalysis.dataModels.edit(':id')}>
        <EditDataModel />
      </Route>,
      { mocks, initialRoute: urls.logAnalysis.dataModels.edit(dataModel.id) }
    );

    // wait for API request to finish
    await waitFor(() => expect(getByLabelText('Display Name')).toHaveValue(dataModel.displayName));

    fireEvent.click(getByPlaceholderText('Toggle Enabled'));
    fireEvent.change(getByLabelText('Display Name'), {
      target: { value: updatedDataModel.displayName },
    });
    fireEvent.change(getAllByLabelText('Log Type')[0], {
      target: { value: updatedDataModel.logTypes[0] },
    });
    fireClickAndMouseEvents(await findByText(updatedDataModel.logTypes[0]));

    fireEvent.change(getByLabelText('Name'), {
      target: { value: updatedDataModel.mappings[0].name },
    });
    fireEvent.change(getByLabelText('Field Method'), {
      target: { value: updatedDataModel.mappings[0].method },
    });

    fireEvent.click(getByAriaLabel('Toggle Python Editor visibility'));
    fireEvent.change(getByPlaceholderText('# Enter the body of this mapping...'), {
      target: { value: updatedDataModel.body },
    });

    // wait for debounce and validations
    await waitMs(1);

    fireEvent.click(getByText('Save'));

    expect(await findByText('Successfully updated your Data Model')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedDataModel,
      src: SrcEnum.DataModels,
    });
  });

  it('can handle errors', async () => {
    const dataModel = buildDataModel({
      id: 'test',
      displayName: 'test',
      logTypes: ['AWS.ALB'],
      enabled: true,
      mappings: [buildDataModelMapping({ name: 'test-name', method: 'test-method', path: '' })],
      body: '',
    });

    const updatedDataModel = {
      ...dataModel,
      displayName: 'Updated Name',
    };

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
          input: {
            displayName: updatedDataModel.displayName,
            id: updatedDataModel.id,
            logTypes: updatedDataModel.logTypes,
            enabled: updatedDataModel.enabled,
            mappings: updatedDataModel.mappings.map(m => omit(m, '__typename')),
            body: updatedDataModel.body,
          },
        },
        data: null,
        errors: [new GraphQLError('Fake Error Message')],
      }),
    ];

    const { getByText, getByLabelText, findByText } = render(
      <Route exact path={urls.logAnalysis.dataModels.edit(':id')}>
        <EditDataModel />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.dataModels.edit(dataModel.id),
      }
    );

    // wait for API request to finish
    await waitFor(() => expect(getByLabelText('Display Name')).toHaveValue(dataModel.displayName));

    fireEvent.change(getByLabelText('Display Name'), {
      target: { value: updatedDataModel.displayName },
    });

    // wait for validation to kick in
    await waitMs(100);
    fireEvent.click(getByText('Save'));

    expect(await findByText('Fake Error Message')).toBeInTheDocument();

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToUpdateDataModel,
      src: SrcEnum.DataModels,
    });
  });
});
