import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import { buildDeliveryResponse, buildDestination, render } from 'test-utils';
import AlertDeliveryTable from './index';

describe('AlertDeliveryTable', () => {
  it('renders information about a list of delivery Responses', () => {
    const alertDelivery = buildDeliveryResponse({ success: false });
    const destination = buildDestination({ outputId: alertDelivery.outputId });

    const enhancedAlertDelivery = {
      ...alertDelivery,
      outputType: destination.outputType,
      displayName: destination.displayName,
    };

    const { getByText, getByAriaLabel } = render(
      <AlertDeliveryTable
        alertDeliveries={[enhancedAlertDelivery]}
        onAlertDeliveryRetry={() => {}}
      />
    );

    expect(getByText(formatDatetime(alertDelivery.dispatchedAt))).toBeInTheDocument();
    expect(getByText(alertDelivery.statusCode.toString())).toBeInTheDocument();
    expect(getByText('FAIL')).toBeInTheDocument();
    expect(getByAriaLabel('Retry delivery')).toBeInTheDocument();
    expect(getByAriaLabel('Expand delivery information')).toBeInTheDocument();

    // TODO: add more assertions once feature is complete
  });

  it('doesn\'t render a "retry" button for  successful deliveries', () => {
    const alertDelivery = buildDeliveryResponse({ success: true });
    const destination = buildDestination({ outputId: alertDelivery.outputId });

    const enhancedAlertDelivery = {
      ...alertDelivery,
      outputType: destination.outputType,
      displayName: destination.displayName,
    };

    const { getByText, queryByAriaLabel } = render(
      <AlertDeliveryTable
        alertDeliveries={[enhancedAlertDelivery]}
        onAlertDeliveryRetry={() => {}}
      />
    );

    expect(getByText('SUCCESS')).toBeInTheDocument();
    expect(queryByAriaLabel('Retry delivery')).not.toBeInTheDocument();
  });
});
