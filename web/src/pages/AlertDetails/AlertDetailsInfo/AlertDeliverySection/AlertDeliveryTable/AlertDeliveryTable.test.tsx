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
import { buildDeliveryResponse, render } from 'test-utils';
import AlertDeliveryTable from './index';

describe('AlertDeliveryTable', () => {
  it('renders information about a list of delivery Responses', () => {
    const alertDelivery = buildDeliveryResponse({ success: false });
    const { getByText, getByAriaLabel } = render(
      <AlertDeliveryTable alertDeliveries={[alertDelivery]} />
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
    const { getByText, queryByAriaLabel } = render(
      <AlertDeliveryTable alertDeliveries={[alertDelivery]} />
    );

    expect(getByText('SUCCESS')).toBeInTheDocument();
    expect(queryByAriaLabel('Retry delivery')).not.toBeInTheDocument();
  });
});
