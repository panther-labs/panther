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
import { buildCustomLogRecord, fireClickAndMouseEvents, render, waitFor } from 'test-utils';
import { GraphQLError } from 'graphql';
import { mockDeleteCustomLog } from 'Components/modals/DeleteCustomLogModal/graphql/deleteCustomLog.generated';
import ListCustomLogs from './ListCustomLogs';
import { mockListCustomLogSchemas } from './graphql/listCustomLogSchemas.generated';

describe('ListCustomLogs', () => {
  it('renders loading animation', () => {
    const { getByAriaLabel } = render(<ListCustomLogs />);

    expect(getByAriaLabel('Loading interface...')).toBeInTheDocument();
  });

  it('renders a fallback when no custom sources are present', async () => {
    const mocks = [mockListCustomLogSchemas({ data: { listCustomLogs: [] } })];
    const { findByAltText, getByText } = render(<ListCustomLogs />, { mocks });

    expect(await findByAltText('Empty data illustration')).toBeInTheDocument();
    expect(getByText("You don't have any custom schemas")).toBeInTheDocument();
  });

  it('renders an error box when an exception occurs', async () => {
    const mocks = [
      mockListCustomLogSchemas({ data: null, errors: [new GraphQLError('Test Error')] }),
    ];
    const { findByText } = render(<ListCustomLogs />, { mocks });

    expect(await findByText('Test Error')).toBeInTheDocument();
  });

  it('renders a list of custom schemas', async () => {
    const customLogs = [
      buildCustomLogRecord({ logType: 'Custom.Log.1' }),
      buildCustomLogRecord({ logType: 'Custom.Log.2' }),
    ];

    const mocks = [mockListCustomLogSchemas({ data: { listCustomLogs: customLogs } })];
    const { findByText } = render(<ListCustomLogs />, { mocks });

    expect(await findByText(customLogs[0].logType)).toBeInTheDocument();
    expect(await findByText(customLogs[1].logType)).toBeInTheDocument();
  });

  it('removes a custom schema upon successful deletion', async () => {
    const customLogs = [
      buildCustomLogRecord({ logType: 'Custom.Log.1' }),
      buildCustomLogRecord({ logType: 'Custom.Log.2' }),
    ];

    const customLogToDelete = customLogs[0];
    const mocks = [
      mockListCustomLogSchemas({ data: { listCustomLogs: customLogs } }),
      mockDeleteCustomLog({
        variables: {
          input: { logType: customLogToDelete.logType, revision: customLogToDelete.revision },
        },
        data: { deleteCustomLog: { error: null } },
      }),
    ];
    const { getByText, getAllByAriaLabel, findByText } = render(<ListCustomLogs />, { mocks });

    const deletionNode = await findByText(customLogToDelete.logType);
    expect(deletionNode).toBeInTheDocument();

    fireClickAndMouseEvents(getAllByAriaLabel('Toggle Options')[0]);
    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));
    await waitFor(() => {
      expect(deletionNode).not.toBeInTheDocument();
    });
  });

  it('shows an error upon unsuccessful deletion', async () => {
    const customLogs = [
      buildCustomLogRecord({ logType: 'Custom.Log.1' }),
      buildCustomLogRecord({ logType: 'Custom.Log.2' }),
    ];

    const customLogToDelete = customLogs[0];
    const mocks = [
      mockListCustomLogSchemas({ data: { listCustomLogs: customLogs } }),
      mockDeleteCustomLog({
        variables: {
          input: {
            logType: customLogToDelete.logType,
            revision: customLogToDelete.revision,
          },
        },
        data: { deleteCustomLog: { error: { message: 'Test Error' } } },
      }),
    ];
    const { getByText, getAllByAriaLabel, findByText } = render(<ListCustomLogs />, { mocks });

    await findByText(customLogToDelete.logType);

    fireClickAndMouseEvents(getAllByAriaLabel('Toggle Options')[0]);
    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));

    expect(await findByText('Test Error')).toBeInTheDocument();
  });

  it('shows a default message upon a runtime error', async () => {
    const customLogs = [
      buildCustomLogRecord({ logType: 'Custom.Log.1' }),
      buildCustomLogRecord({ logType: 'Custom.Log.2' }),
    ];

    const customLogToDelete = customLogs[0];
    const mocks = [
      mockListCustomLogSchemas({ data: { listCustomLogs: customLogs } }),
      mockDeleteCustomLog({
        variables: {
          input: {
            logType: customLogToDelete.logType,
            revision: customLogToDelete.revision,
          },
        },
        data: null,
        errors: [new GraphQLError('Error')],
      }),
    ];
    const { getByText, getAllByAriaLabel, findByText } = render(<ListCustomLogs />, { mocks });

    await findByText(customLogToDelete.logType);

    fireClickAndMouseEvents(getAllByAriaLabel('Toggle Options')[0]);
    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));

    expect(await findByText('Failed to delete your custom schema')).toBeInTheDocument();
  });
});
