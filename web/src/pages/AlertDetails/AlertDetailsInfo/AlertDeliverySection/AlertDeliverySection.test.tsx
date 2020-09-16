import React from 'react';
import {
  buildDeliveryResponse,
  render,
  fireEvent,
  waitForElementToBeRemoved,
  buildAlertDetails,
} from 'test-utils';
import AlertDeliverySection from './index';

describe('AlertDeliveryTable', () => {
  it('renders the correct message on successful alert delivery', () => {
    const deliveryResponses = [buildDeliveryResponse({ success: true })];
    const alert = buildAlertDetails({ deliveryResponses });

    const { queryByText } = render(<AlertDeliverySection alert={alert} alertDestinations={[]} />);

    expect(queryByText('Alert was delivered successfully')).toBeInTheDocument();
    expect(queryByText('Show History')).toBeInTheDocument();
  });

  it('renders the correct message on failed alert delivery', () => {
    const deliveryResponses = [buildDeliveryResponse({ success: false })];
    const alert = buildAlertDetails({ deliveryResponses });

    const { queryByText } = render(<AlertDeliverySection alert={alert} alertDestinations={[]} />);

    expect(queryByText('Alert delivery failed')).toBeInTheDocument();
    expect(queryByText('Show History')).toBeInTheDocument();
  });

  it('renders the correct message on no alert deliverires', () => {
    const alert = buildAlertDetails({ deliveryResponses: [] });

    const { queryByText } = render(<AlertDeliverySection alert={alert} alertDestinations={[]} />);

    expect(queryByText('Delivery information could not be retrieved')).toBeInTheDocument();
    expect(queryByText('Show History')).not.toBeInTheDocument();
  });

  it('correctly toggles between showing and hiding the  delivery table', async () => {
    const deliveryResponses = [buildDeliveryResponse({ success: false })];
    const alert = buildAlertDetails({ deliveryResponses });

    const { queryByText, queryByTestId } = render(
      <AlertDeliverySection alert={alert} alertDestinations={[]} />
    );

    expect(queryByTestId('alert-delivery-table')).not.toBeInTheDocument();

    fireEvent.click(queryByText('Show History'));
    expect(queryByTestId('alert-delivery-table')).toBeInTheDocument();

    fireEvent.click(queryByText('Hide History'));
    await waitForElementToBeRemoved(queryByTestId('alert-delivery-table'));
    expect(queryByTestId('alert-delivery-table')).not.toBeInTheDocument();
  });
});
