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
import { render, buildPolicy } from 'test-utils';
import PolicyDetailsBanner from './PolicyDetailsBanner';

describe('PolicyDetailsBanner', () => {
  it('renders the correct data', async () => {
    const policy = buildPolicy({ displayName: 'My Policy' });
    const { getByText } = render(<PolicyDetailsBanner policy={policy} />);
    expect(getByText('Edit Policy')).toBeInTheDocument();
    expect(getByText('Delete Policy')).toBeInTheDocument();

    expect(getByText('My Policy')).toBeInTheDocument();
    expect(getByText('FAIL')).toBeInTheDocument();
    expect(getByText('MEDIUM')).toBeInTheDocument();
    expect(getByText('AUTO REMEDIATIATABLE')).toBeInTheDocument();
  });
});
