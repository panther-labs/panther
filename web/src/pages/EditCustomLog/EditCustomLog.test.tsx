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
  buildCustomLogOutput,
  buildCustomLogRecord,
  fireEvent,
  render,
  waitFor,
  waitMs,
} from 'test-utils';

import { Route } from 'react-router';
import urls from 'Source/urls';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import { mockGetCustomLogDetails } from 'Pages/CustomLogDetails/graphql/getCustomLogDetails.generated';
import EditCustomLog from './EditCustomLog';
import { mockUpdateCustomLog } from './graphql/updateCustomLog.generated';

jest.mock('Helpers/analytics');

const build = (opts = {}) =>
  buildCustomLogRecord({
    logType: 'Custom.Test',
    ...opts,
    logSpec:
      'schema: Test\n' +
      'version: 0\n' +
      'fields:\n' +
      '  - name: method\n' +
      '    description: Test' +
      '    type: string',
  });

describe('EditCustomLog', () => {
  it('renders the form values', async () => {
    const customLog = build({ revision: 1 });
    const mocks = [
      mockGetCustomLogDetails({
        variables: {
          input: {
            logType: customLog.logType,
          },
        },
        data: {
          getCustomLog: {
            record: customLog,
            error: null,
          },
        },
      }),
      mockUpdateCustomLog({
        variables: {
          input: {
            logType: customLog.logType,
            logSpec: customLog.logSpec,
            description: '',
            referenceURL: '',
          },
        },
        data: { updateCustomLog: buildCustomLogOutput({ error: null, record: customLog }) },
      }),
    ];

    const { getByText, getByLabelText, getByPlaceholderText } = render(
      <Route exact path={urls.logAnalysis.customLogs.edit(':logType')}>
        <EditCustomLog />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.customLogs.edit(customLog.logType),
      }
    );

    await waitFor(() => {
      expect(getByText('Update log')).toBeInTheDocument();
    });
    expect(getByText('Update log')).toHaveAttribute('disabled');
    expect(getByLabelText('* Name')).toHaveValue(customLog.logType);
    expect(getByLabelText('* Name')).toHaveAttribute('disabled');
    expect(getByLabelText('Description')).toHaveValue(customLog.description);
    expect(getByPlaceholderText('# Write your schema in YAML here...')).toHaveValue(
      customLog.logSpec
    );
    expect(getByLabelText('Reference URL')).toHaveValue(customLog.referenceURL);
  });

  it('allows updating the custom log schema', async () => {
    const customLog = build({ revision: 1 });
    const updatedCustomLog = build({
      revision: 1,
      referenceURL: 'https://runpanther.io',
      description: 'Test test',
    });
    const mocks = [
      mockGetCustomLogDetails({
        variables: {
          input: {
            logType: customLog.logType,
          },
        },
        data: {
          getCustomLog: {
            record: customLog,
            error: null,
          },
        },
      }),
      mockUpdateCustomLog({
        variables: {
          input: {
            revision: updatedCustomLog.revision,
            logType: updatedCustomLog.logType,
            logSpec: updatedCustomLog.logSpec,
            description: updatedCustomLog.description,
            referenceURL: updatedCustomLog.referenceURL,
          },
        },
        data: {
          updateCustomLog: buildCustomLogOutput({
            error: null,
            record: { ...customLog, revision: 2 },
          }),
        },
      }),
    ];

    const { getByText, getByLabelText } = render(
      <Route exact path={urls.logAnalysis.customLogs.edit(':logType')}>
        <EditCustomLog />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.customLogs.edit(customLog.logType),
      }
    );

    await waitFor(() => {
      expect(getByText('Update log')).toBeInTheDocument();
    });

    fireEvent.change(getByLabelText('Description'), {
      target: { value: updatedCustomLog.description },
    });
    fireEvent.change(getByLabelText('Reference URL'), {
      target: { value: updatedCustomLog.referenceURL },
    });

    await waitMs(210); // wait for debounce to apply the value to <Formik> + perform validation
    fireEvent.click(getByText('Update log'));

    await waitFor(() => {
      expect(getByText('Successfully updated custom log schema!')).toBeInTheDocument();
    });

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.UpdatedCustomLog,
      src: SrcEnum.CustomLogs,
    });
  });
});
