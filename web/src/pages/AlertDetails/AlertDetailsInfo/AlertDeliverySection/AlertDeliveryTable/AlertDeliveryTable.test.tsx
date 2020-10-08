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
        isResending={false}
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
        isResending={false}
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
        isResending={false}
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
        isResending={false}
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
        isResending={false}
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
