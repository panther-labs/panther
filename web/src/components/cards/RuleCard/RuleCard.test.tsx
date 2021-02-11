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
import { buildRule, render } from 'test-utils';
import { SeverityEnum } from 'Generated/schema';
import { SelectProvider } from 'Components/utils/SelectContext';
import urls from 'Source/urls';
import RuleCard from './index';

describe('RuleCard', () => {
  it('displays the correct Alert data in the card', async () => {
    const rule = buildRule();

    const { getByText } = render(<RuleCard rule={rule} />);

    expect(getByText(rule.displayName)).toBeInTheDocument();
    expect(getByText('Destinations')).toBeInTheDocument();
    expect(getByText(SeverityEnum.High)).toBeInTheDocument();
    expect(getByText('DISABLED')).toBeInTheDocument();
  });

  it('should check links are valid', async () => {
    const rule = buildRule();

    const { getByAriaLabel } = render(<RuleCard rule={rule} />);
    expect(getByAriaLabel('Link to Rule')).toHaveAttribute(
      'href',
      urls.logAnalysis.rules.details(rule.id)
    );
  });

  it('renders a checkbox when selection is enabled', () => {
    const { getByAriaLabel } = render(
      <SelectProvider>
        <RuleCard rule={buildRule()} selectionEnabled />
      </SelectProvider>
    );

    expect(getByAriaLabel(`select item`)).toBeInTheDocument();
  });
});
