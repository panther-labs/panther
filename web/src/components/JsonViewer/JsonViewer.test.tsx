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
import { render, fireEvent, waitFor, waitMs } from 'test-utils';
import JsonViewer from './JsonViewer';

const demoJson = {
  TestingReactLazy: {
    header: 'Test',
    items: [
      { id: 'Foo' },
      { id: 'Bar', label: 'Baz' },
      null,
      { id: 'Test' },
      { id: 'Qux', label: 'Lorem ipsum, dolor foo bar' },
    ],
  },
};

describe('JsonViewer', () => {
  it('renders', async () => {
    const { container, getByText } = render(<JsonViewer data={demoJson} />);
    await waitFor(() => expect(getByText('TestingReactLazy')).toBeInTheDocument());
    expect(container).toMatchSnapshot();
  });

  it('toggles and expands the json view tree', async () => {
    const { container, getByTestId, getByText } = render(<JsonViewer data={demoJson} />);
    await waitFor(() => expect(getByText('TestingReactLazy')).toBeInTheDocument());
    expect(container).toMatchSnapshot();
    fireEvent.click(getByTestId('toggle-json'));
    await waitMs(1);
    expect(container).toMatchSnapshot();
  });
});
