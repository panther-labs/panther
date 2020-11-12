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
import { buildRuleSummary, render } from 'test-utils';
import { SeverityEnum } from 'Generated/schema';
import urls from 'Source/urls';
import RuleCard from './index';

describe('RuleCard', () => {
  it('displays the correct Alert data in the card', async () => {
    const ruleData = buildRuleSummary();

    const { getByText } = render(<RuleCard rule={ruleData} />);

    expect(getByText(ruleData.displayName)).toBeInTheDocument();
    expect(getByText('Threshold')).toBeInTheDocument();
    expect(getByText('Last Modified')).toBeInTheDocument();
    expect(getByText('Destinations')).toBeInTheDocument();
    expect(getByText(SeverityEnum.Info)).toBeInTheDocument();
    expect(getByText('DISABLED')).toBeInTheDocument();
  });

  it('should check links are valid', async () => {
    const ruleData = buildRuleSummary();

    const { getByAriaLabel } = render(<RuleCard rule={ruleData} />);
    expect(getByAriaLabel('Link to Rule')).toHaveAttribute(
      'href',
      urls.logAnalysis.rules.details(ruleData.id)
    );
  });
});
