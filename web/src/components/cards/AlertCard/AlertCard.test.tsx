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

import { buildAlertSummary, render } from 'test-utils';
import React from 'react';
import { AlertStatusesEnum, SeverityEnum } from 'Generated/schema';
import urls from 'Source/urls';
import AlertCard from './index';

describe('AlertCard', () => {
  it('displays the correct Alert data in the card', async () => {
    const alertData = buildAlertSummary();

    const { getByText, getByAriaLabel } = render(<AlertCard alert={alertData} />);

    expect(getByText(alertData.title)).toBeInTheDocument();
    expect(getByText('View Rule')).toBeInTheDocument();
    expect(getByText('Events')).toBeInTheDocument();
    expect(getByText('Time Created')).toBeInTheDocument();
    expect(getByText(SeverityEnum.Medium)).toBeInTheDocument();
    expect(getByText(AlertStatusesEnum.Triaged)).toBeInTheDocument();
    expect(getByAriaLabel('Change Alert Status')).toBeInTheDocument();
  });

  it('should check links are valid', async () => {
    const alertData = buildAlertSummary();
    const { getByAriaLabel } = render(<AlertCard alert={alertData} />);
    expect(getByAriaLabel('Link to Alert')).toHaveAttribute(
      'href',
      urls.logAnalysis.alerts.details(alertData.alertId)
    );
    expect(getByAriaLabel('Link to Rule')).toHaveAttribute(
      'href',
      urls.logAnalysis.rules.details(alertData.ruleId)
    );
  });
});
