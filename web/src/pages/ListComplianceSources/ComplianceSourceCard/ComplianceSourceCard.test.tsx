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

import { render, buildComplianceIntegration } from 'test-utils';
import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import ComplianceSourceCard from './index';

describe('ComplianceSourceCard', () => {
  it('displays the needed data', async () => {
    const source = buildComplianceIntegration();
    const { getByText, getByAriaLabel, getByAltText } = render(
      <ComplianceSourceCard source={source} />
    );

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    expect(getByAriaLabel(/Toggle Options/i)).toBeInTheDocument();
    expect(getByText(source.integrationLabel)).toBeInTheDocument();
    expect(getByText(source.awsAccountId)).toBeInTheDocument();
    expect(getByAriaLabel(/Real-Time AWS Resource Scans enabled/i)).toBeInTheDocument();
    expect(getByAriaLabel(/AWS Automatic Remediations disabled/i)).toBeInTheDocument();
    expect(getByText(/Unhealthy/i)).toBeInTheDocument();
    expect(getByText(formatDatetime(source.createdAtTime))).toBeInTheDocument();
  });
});
