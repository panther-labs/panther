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
import { render, fireEvent } from 'test-utils';
import LimitItemDisplay from './LimitItemDisplay';

describe('LimitItemDisplay', () => {
  it('shows all the items if they are equal to or less than the limit', () => {
    const { getByText } = render(
      <LimitItemDisplay limit={2}>
        <div>One</div>
        <div>Two</div>
      </LimitItemDisplay>
    );

    expect(getByText('One')).toBeInTheDocument();
    expect(getByText('Two')).toBeInTheDocument();
  });

  it('shows less items if they are more than the limit and displays the rest in a tooltip', async () => {
    const { queryByText, findByText } = render(
      <LimitItemDisplay limit={2}>
        <div>One</div>
        <div>Two</div>
        <div>Three</div>
        <div>Four</div>
      </LimitItemDisplay>
    );

    expect(queryByText('Three')).not.toBeInTheDocument();
    expect(queryByText('Four')).not.toBeInTheDocument();

    fireEvent.mouseEnter(queryByText('+2'));

    expect(await findByText('Three')).toBeInTheDocument();
    expect(queryByText('Four')).toBeInTheDocument();
  });

  it('matches snapshot', async () => {
    const { container, getByText, findByText } = render(
      <LimitItemDisplay limit={2}>
        <div>One</div>
        <div>Two</div>
        <div>Three</div>
        <div>Four</div>
      </LimitItemDisplay>
    );
    expect(container).toMatchSnapshot();

    fireEvent.mouseEnter(getByText('+2'));
    expect(await findByText('Three')).toBeInTheDocument();

    expect(container).toMatchSnapshot();
  });
});
