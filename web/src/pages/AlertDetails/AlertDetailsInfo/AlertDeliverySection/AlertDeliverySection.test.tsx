import React from 'react';
import { buildDeliveryResponse, render, fireEvent, waitForElementToBeRemoved } from 'test-utils';
import AlertDeliverySection from './index';

describe('AlertDeliveryTable', () => {
  it('renders the correct message on successful alert delivery', () => {
    const alertDelivery = buildDeliveryResponse({ success: true });
    const { queryByText } = render(<AlertDeliverySection alertDeliveries={[alertDelivery]} />);

    expect(queryByText('Alert was delivered successfully')).toBeInTheDocument();
    expect(queryByText('Show History')).toBeInTheDocument();
  });

  it('renders the correct message on failed alert delivery', () => {
    const alertDelivery = buildDeliveryResponse({ success: false });
    const { queryByText } = render(<AlertDeliverySection alertDeliveries={[alertDelivery]} />);

    expect(queryByText('Alert delivery failed')).toBeInTheDocument();
    expect(queryByText('Show History')).toBeInTheDocument();
  });

  it('renders the correct message on no alert deliverires', () => {
    const { queryByText } = render(<AlertDeliverySection alertDeliveries={[]} />);

    expect(queryByText('Delivery information could not be retrieved')).toBeInTheDocument();
    expect(queryByText('Show History')).not.toBeInTheDocument();
  });

  it('correctly toggles between showing and hiding the  delivery table', async () => {
    const alertDelivery = buildDeliveryResponse({ success: false });
    const { queryByText, queryByTestId } = render(
      <AlertDeliverySection alertDeliveries={[alertDelivery]} />
    );

    expect(queryByTestId('alert-delivery-table')).not.toBeInTheDocument();

    fireEvent.click(queryByText('Show History'));
    expect(queryByTestId('alert-delivery-table')).toBeInTheDocument();

    fireEvent.click(queryByText('Hide History'));
    await waitForElementToBeRemoved(queryByTestId('alert-delivery-table'));
    expect(queryByTestId('alert-delivery-table')).not.toBeInTheDocument();
  });
});
