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

import { render, buildSqsLogSourceIntegration } from 'test-utils';
import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import { SqsLogSourceCard } from './index';

describe('SqsLogSourceCard', () => {
  it('displays the needed data for Sqs', async () => {
    const source = buildSqsLogSourceIntegration();
    const { getByText, getByAriaLabel, getByAltText } = render(
      <SqsLogSourceCard source={source} />
    );

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    expect(getByAriaLabel(/Toggle Options/i)).toBeInTheDocument();
    expect(getByText(source.integrationLabel)).toBeInTheDocument();
    source.sqsConfig.allowedPrincipalArns.forEach(arn => {
      expect(getByText(arn)).toBeInTheDocument();
    });
    source.sqsConfig.allowedSourceArns.forEach(arn => {
      expect(getByText(arn)).toBeInTheDocument();
    });
    expect(getByText(formatDatetime(source.createdAtTime, true))).toBeInTheDocument();
    source.sqsConfig.logTypes.forEach(logType => {
      expect(getByText(logType)).toBeInTheDocument();
    });
  });
});
