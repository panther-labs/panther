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
import { render, buildRule } from 'test-utils';
import RuleCardDetails from './index';

describe('RuleDetailsInfo', () => {
  it('renders the correct data', async () => {
    const rule = buildRule({
      displayName: 'My Rule',
      description: 'This is an amazing description',
      runbook: 'Panther labs runbook',
      reference: 'Panther labs reference',
      dedupPeriodMinutes: 14,
      threshold: 101,
      tags: ['hello', 'world'],
    });
    const { getByText } = render(<RuleCardDetails rule={rule} />);
    expect(getByText('This is an amazing description')).toBeInTheDocument();

    expect(getByText('Runbook')).toBeInTheDocument();
    expect(getByText('Panther labs runbook')).toBeInTheDocument();

    expect(getByText('Reference')).toBeInTheDocument();
    expect(getByText('Panther labs reference')).toBeInTheDocument();

    expect(getByText('Tags')).toBeInTheDocument();

    expect(getByText('Threshold')).toBeInTheDocument();
    expect(getByText('101')).toBeInTheDocument();

    expect(getByText('Deduplication Period')).toBeInTheDocument();
    expect(getByText('14min')).toBeInTheDocument();

    expect(getByText('Modified')).toBeInTheDocument();
    expect(getByText('Created')).toBeInTheDocument();
  });
});
