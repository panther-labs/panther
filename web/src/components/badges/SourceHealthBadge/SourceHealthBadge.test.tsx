import React from 'react';
import { buildIntegrationItemHealthStatus, render, fireEvent } from 'test-utils';
import SourceHealthBadge from './index';

describe('SourceHealthBadge', () => {
  it('matches original snapshoot', () => {
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
