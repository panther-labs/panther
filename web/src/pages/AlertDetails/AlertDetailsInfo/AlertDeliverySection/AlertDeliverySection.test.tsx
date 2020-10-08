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
import {
  buildDeliveryResponse,
  render,
  fireEvent,
  waitForElementToBeRemoved,
  buildAlertDetails,
  buildDestination,
} from 'test-utils';
import AlertDeliverySection from './index';

describe('AlertDeliveryTable', () => {
  it('renders the correct message on successful alert delivery', () => {
    const deliveryResponses = [
      buildDeliveryResponse({ success: false, dispatchedAt: '2020-10-08T12:00:00.000000000Z' }),
      buildDeliveryResponse({ success: true, dispatchedAt: '2020-10-08T12:00:00.000000001Z' }),
    ];
    const alert = buildAlertDetails({ deliveryResponses });
    const destination = buildDestination({ outputId: alert.deliveryResponses[0].outputId });

    const { queryByText } = render(
      <AlertDeliverySection alert={alert} alertDestinations={[destination]} />
    );

    expect(queryByText('Alert was delivered successfully')).toBeInTheDocument();
    expect(queryByText('Show History')).toBeInTheDocument();
  });

  it('renders the correct message on failed alert delivery', () => {
    const deliveryResponses = [
      buildDeliveryResponse({ success: true, dispatchedAt: '2020-10-08T12:00:00.000000000Z' }),
      buildDeliveryResponse({ success: false, dispatchedAt: '2020-10-08T12:00:00.000000001Z' }),
    ];
    const alert = buildAlertDetails({ deliveryResponses });
    const destination = buildDestination({ outputId: alert.deliveryResponses[0].outputId });

    const { queryByText } = render(
      <AlertDeliverySection alert={alert} alertDestinations={[destination]} />
    );

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
    const destination = buildDestination({ outputId: alert.deliveryResponses[0].outputId });

    const { queryByText, queryByTestId } = render(
      <AlertDeliverySection alert={alert} alertDestinations={[destination]} />
    );

    expect(queryByTestId('alert-delivery-table')).not.toBeInTheDocument();

    fireEvent.click(queryByText('Show History'));
    expect(queryByTestId('alert-delivery-table')).toBeInTheDocument();

    fireEvent.click(queryByText('Hide History'));
    await waitForElementToBeRemoved(queryByTestId('alert-delivery-table'));
    expect(queryByTestId('alert-delivery-table')).not.toBeInTheDocument();
  });
});
