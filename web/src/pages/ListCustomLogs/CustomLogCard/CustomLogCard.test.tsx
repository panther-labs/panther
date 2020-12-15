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
import { buildCustomLogRecord, fireClickAndMouseEvents, render } from 'test-utils';
import CustomLogCard from 'Pages/ListCustomLogs/CustomLogCard/CustomLogCard';
import { formatDatetime } from 'Helpers/utils';
import urls from 'Source/urls';

describe('CustomLogCard', () => {
  it('matches snapshot', () => {
    const customLog = buildCustomLogRecord();
    const { container } = render(<CustomLogCard customLog={customLog} />);

    expect(container).toMatchSnapshot();
  });

  it('renders the correct information', () => {
    const customLog = buildCustomLogRecord();
    const { container, getByText } = render(<CustomLogCard customLog={customLog} />);

    expect(getByText(customLog.logType)).toBeInTheDocument();
    expect(getByText(customLog.description)).toBeInTheDocument();
    expect(getByText(customLog.referenceURL)).toBeInTheDocument();
    expect(getByText(formatDatetime(customLog.updatedAt))).toBeInTheDocument();
    expect(
      container.querySelector(`a[href="${urls.logAnalysis.customLogs.details(customLog.logType)}"]`)
    ).toBeTruthy();
  });

  it('renders a dropdown with a delete option', () => {
    const customLog = buildCustomLogRecord();
    const { getByText, getByAriaLabel } = render(<CustomLogCard customLog={customLog} />);

    fireClickAndMouseEvents(getByAriaLabel('Toggle Options'));
    expect(getByText('Delete')).toBeInTheDocument();
  });
});
