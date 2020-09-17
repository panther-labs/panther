import React from 'react';
import { formatDatetime } from 'Helpers/utils';
import { DeliveryResponse } from 'Generated/schema';
import { buildDeliveryResponse, buildDestination, render, fireEvent } from 'test-utils';
import AlertDeliveryTable from './index';

const enhanceAlertDelivery = (alertDelivery: DeliveryResponse) => {
  const destination = buildDestination({ outputId: alertDelivery.outputId });
  return {
    ...alertDelivery,
    outputType: destination.outputType,
    displayName: destination.displayName,
  };
};

describe('AlertDeliveryTable', () => {
  it('renders information about a list of delivery Responses', () => {
    const alertDelivery = buildDeliveryResponse({ success: false });
    const enhancedAlertDelivery = enhanceAlertDelivery(alertDelivery);

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
    expect(getByText(enhancedAlertDelivery.displayName)).toBeInTheDocument();
    expect(getByText('1')).toBeInTheDocument();
  });

  it('doesn\'t render a "retry" button for  successful deliveries', () => {
    const alertDelivery = buildDeliveryResponse({ success: true });
    const enhancedAlertDelivery = enhanceAlertDelivery(alertDelivery);

    const { getByText, queryByAriaLabel } = render(
      <AlertDeliveryTable
        alertDeliveries={[enhancedAlertDelivery]}
        onAlertDeliveryRetry={() => {}}
      />
    );

    expect(getByText('SUCCESS')).toBeInTheDocument();
    expect(queryByAriaLabel('Retry delivery')).not.toBeInTheDocument();
  });

  it('retry button calls `onAlertDeliveryRetry` with correct args', () => {
    const alertDelivery = buildDeliveryResponse({ success: false });
    const enhancedAlertDelivery = enhanceAlertDelivery(alertDelivery);

    const onAlertDeliveryRetry = jest.fn();
    const { getByAriaLabel } = render(
      <AlertDeliveryTable
        alertDeliveries={[enhancedAlertDelivery]}
        onAlertDeliveryRetry={onAlertDeliveryRetry}
      />
    );

    fireEvent.click(getByAriaLabel('Retry delivery'));
    expect(onAlertDeliveryRetry).toHaveBeenCalledTimes(1);
    expect(onAlertDeliveryRetry).toHaveBeenCalledWith(enhancedAlertDelivery.outputId);
  });

  it('doesn\'t render a "row expand" button if destination delivery was never retried', () => {
    const alertDelivery = buildDeliveryResponse();
    const enhancedAlertDelivery = enhanceAlertDelivery(alertDelivery);

    const { queryByAriaLabel } = render(
      <AlertDeliveryTable
        alertDeliveries={[enhancedAlertDelivery]}
        onAlertDeliveryRetry={() => {}}
      />
    );

    expect(queryByAriaLabel('Expand delivery information')).not.toBeInTheDocument();
  });

  it('renders a row working "row expand" button if destination delivery was retried', () => {
    const failedAlertDelivery = buildDeliveryResponse({ success: false });
    const successfulAlertDelivery = buildDeliveryResponse({ success: true });

    const enhancedFailedAlertDelivery = enhanceAlertDelivery(failedAlertDelivery);
    const enhancedSuccessfulAlertDelivery = enhanceAlertDelivery(successfulAlertDelivery);

    const { queryByText, queryByAriaLabel } = render(
      <AlertDeliveryTable
        alertDeliveries={[enhancedSuccessfulAlertDelivery, enhancedFailedAlertDelivery]}
        onAlertDeliveryRetry={() => {}}
      />
    );

    // Expect to see 1 row
    const expandButton = queryByAriaLabel('Expand delivery information');
    expect(expandButton).toBeInTheDocument();
    expect(queryByText('SUCCESS')).toBeInTheDocument();
    expect(queryByText('FAIL')).not.toBeInTheDocument();

    // Expect for items to be expanded and to see 2 rows - both items
    fireEvent.click(expandButton);
    expect(queryByText('SUCCESS')).toBeInTheDocument();
    expect(queryByText('FAIL')).toBeInTheDocument();

    // Expect for items to be hidden and to to see again only the first row
    fireEvent.click(expandButton);
    expect(queryByText('SUCCESS')).toBeInTheDocument();
    expect(queryByText('FAIL')).not.toBeInTheDocument();
  });
});
