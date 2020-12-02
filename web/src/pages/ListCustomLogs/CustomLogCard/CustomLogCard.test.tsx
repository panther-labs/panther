/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
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
