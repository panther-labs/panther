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
import { buildIntegrationItemHealthStatus, render, fireEvent } from 'test-utils';
import SourceHealthBadge from './index';

describe('SourceHealthBadge', () => {
  it('matches original snapshot', () => {
    const { container } = render(
      <SourceHealthBadge healthMetrics={[buildIntegrationItemHealthStatus()]} />
    );

    expect(container).toMatchSnapshot();
  });

  it('correctly displays "HEALTHY" message', () => {
    const healthMetrics = [buildIntegrationItemHealthStatus({ healthy: true })];
    const { getByText } = render(<SourceHealthBadge healthMetrics={healthMetrics} />);

    expect(getByText('HEALTHY')).toBeInTheDocument();
  });

  it('correctly displays "UNHEALTHY" message', () => {
    const healthMetrics = [buildIntegrationItemHealthStatus({ healthy: false })];
    const { getByText } = render(<SourceHealthBadge healthMetrics={healthMetrics} />);

    expect(getByText('UNHEALTHY')).toBeInTheDocument();
  });

  it('correctly displays passing & failing health checks', async () => {
    const healthMetrics = [
      buildIntegrationItemHealthStatus({ healthy: true, message: 'Healthy Message' }),
      buildIntegrationItemHealthStatus({ healthy: false, message: 'Unhealthy Message' }),
    ];
    const { getByText, findByText, findByAriaLabel } = render(
      <SourceHealthBadge healthMetrics={healthMetrics} />
    );

    fireEvent.mouseOver(getByText('UNHEALTHY'));

    expect(await findByAriaLabel('Passing')).toBeInTheDocument();
    expect(await findByText('Healthy Message')).toBeInTheDocument();

    expect(await findByAriaLabel('Failing')).toBeInTheDocument();
    expect(await findByText('Healthy Message')).toBeInTheDocument();
  });

  it('shows raw error message for failing health checks', async () => {
    const healthMetrics = [
      buildIntegrationItemHealthStatus({
        healthy: false,
        message: 'Unhealthy Message',
        rawErrorMessage: 'Raw Error',
      }),
    ];

    const { getByText, findByText } = render(<SourceHealthBadge healthMetrics={healthMetrics} />);

    fireEvent.mouseOver(getByText('UNHEALTHY'));
    expect(await findByText('Raw Error')).toBeInTheDocument();
  });
});
