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
import { buildTestPolicyRecord, render } from 'test-utils';
import { ComplianceStatusEnum } from 'Generated/schema';
import PolicyFormTestResult from './PolicyFormTestResult';

describe('PolicyFormTestResult', () => {
  it('shows the necessary information', () => {
    const testResult = buildTestPolicyRecord({ passed: true });

    const { getByText } = render(<PolicyFormTestResult testResult={testResult} />);
    expect(getByText(testResult.name)).toBeInTheDocument();
    expect(getByText(testResult.error.message)).toBeInTheDocument();
    expect(getByText(ComplianceStatusEnum.Pass)).toBeInTheDocument();
  });

  it('matches the snapshot', () => {
    const testResult = buildTestPolicyRecord();

    const { container } = render(<PolicyFormTestResult testResult={testResult} />);
    expect(container).toMatchSnapshot();
  });
});
