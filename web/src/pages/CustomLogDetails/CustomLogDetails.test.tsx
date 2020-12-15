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
import { buildCustomLogRecord, render, fireEvent } from 'test-utils';
import { Route } from 'react-router';
import urls from 'Source/urls';
import { GraphQLError } from 'graphql';
import { ErrorCodeEnum } from 'Generated/schema';
import { mockDeleteCustomLog } from 'Components/modals/DeleteCustomLogModal/graphql/deleteCustomLog.generated';
import { mockGetCustomLogDetails } from './graphql/getCustomLogDetails.generated';
import CustomLogDetails from './CustomLogDetails';

describe('CustomLogDetails', () => {
  it('renders a loading screen animation', () => {
    const { getByAriaLabel } = render(<CustomLogDetails />);

    expect(getByAriaLabel('Loading interface...')).toBeInTheDocument();
  });

  it('renders a 404 screen on NotFound errors', async () => {
    const customLog = buildCustomLogRecord();
    const mocks = [
      mockGetCustomLogDetails({
        variables: {
          input: {
            logType: customLog.logType,
          },
        },
        data: {
          getCustomLog: {
            record: null,
            error: {
              code: ErrorCodeEnum.NotFound,
              message: 'Not Found',
            },
          },
        },
      }),
    ];
    const { findByText } = render(
      <Route exact path={urls.logAnalysis.customLogs.details(':logType')}>
        <CustomLogDetails />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.customLogs.details(customLog.logType),
      }
    );

    expect(await findByText('Not all who wander are lost...')).toBeInTheDocument();
  });

  it('shows message from a generic controlled errors', async () => {
    const customLog = buildCustomLogRecord();
    const mocks = [
      mockGetCustomLogDetails({
        variables: {
          input: {
            logType: customLog.logType,
          },
        },
        data: {
          getCustomLog: {
            record: null,
            error: {
              code: null,
              message: 'Generic Error Message',
            },
          },
        },
      }),
    ];
    const { findByText } = render(
      <Route exact path={urls.logAnalysis.customLogs.details(':logType')}>
        <CustomLogDetails />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.customLogs.details(customLog.logType),
      }
    );

    expect(await findByText('Generic Error Message')).toBeInTheDocument();
  });

  it('handles API runtime errors', async () => {
    const customLog = buildCustomLogRecord();
    const mocks = [
      mockGetCustomLogDetails({
        variables: {
          input: {
            logType: customLog.logType,
          },
        },
        data: null,
        errors: [new GraphQLError('Runtime Error')],
      }),
    ];
    const { findByText } = render(
      <Route exact path={urls.logAnalysis.customLogs.details(':logType')}>
        <CustomLogDetails />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.customLogs.details(customLog.logType),
      }
    );

    expect(await findByText('Runtime Error')).toBeInTheDocument();
  });

  it('renders the required information', async () => {
    const customLog = buildCustomLogRecord();
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
    ];
    const { findByText, getByText } = render(
      <Route exact path={urls.logAnalysis.customLogs.details(':logType')}>
        <CustomLogDetails />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.customLogs.details(customLog.logType),
      }
    );

    expect(await findByText(customLog.logType)).toBeInTheDocument();
    expect(getByText(customLog.logSpec)).toBeInTheDocument();
    expect(getByText(customLog.description)).toBeInTheDocument();
    expect(getByText(customLog.referenceURL)).toBeInTheDocument();
  });

  it('redirects correctly on a delete', async () => {
    const customLog = buildCustomLogRecord();

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
      mockDeleteCustomLog({
        variables: {
          input: {
            logType: customLog.logType,
            revision: customLog.revision,
          },
        },
        data: {
          deleteCustomLog: { error: null },
        },
      }),
    ];
    const { findByText, getByText, history } = render(
      <Route exact path={urls.logAnalysis.customLogs.details(':logType')}>
        <CustomLogDetails />
      </Route>,
      {
        mocks,
        initialRoute: urls.logAnalysis.customLogs.details(customLog.logType),
      }
    );

    await findByText(customLog.logType);

    fireEvent.click(getByText('Delete Log'));
    fireEvent.click(getByText('Confirm'));
    expect(history.location.pathname).toEqual(urls.logAnalysis.customLogs.list());
  });
});
