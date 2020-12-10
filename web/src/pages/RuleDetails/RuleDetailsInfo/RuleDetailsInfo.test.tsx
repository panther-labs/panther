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
import { render, buildRuleDetails } from 'test-utils';
import RuleDetailsInfo from './index';

describe('RuleDetailsInfo', () => {
  it('renders the correct data', async () => {
    const rule = buildRuleDetails({ displayName: 'My Rule' });
    const { getByText } = render(<RuleDetailsInfo rule={rule} />);
    expect(getByText('Edit Rule')).toBeInTheDocument();
    expect(getByText('Delete Rule')).toBeInTheDocument();

    expect(getByText('My Rule')).toBeInTheDocument();
    expect(getByText('DISABLED')).toBeInTheDocument();
    expect(getByText('LOW')).toBeInTheDocument();
  });
});
