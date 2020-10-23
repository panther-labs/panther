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

import {
  buildAlertSummary,
  buildDeliveryResponse,
  buildDestination,
  render,
  waitForElementToBeRemoved,
} from 'test-utils';
import useAlertDestinations from 'Hooks/useAlertDestinations';
import { mockListDestinations } from 'Source/graphql/queries';
import { DestinationTypeEnum } from 'Generated/schema';
import React from 'react';

const Component = ({ alert }) => {
  const { loading, alertDestinations } = useAlertDestinations({ alert });
  return (
    <div>
      {loading ? (
        <div aria-label="Loading">Loading...</div>
      ) : (
        alertDestinations.map(dest => {
          return <div key={dest.outputId}>{dest.displayName}</div>;
        })
      )}
    </div>
  );
};

describe('useAlertDestinations hook tests', () => {
  it('should display loading & display destination name', async () => {
    const outputId = 'destination-of-alert';
    const displayName = 'Slack Destination';
    const alert = buildAlertSummary({
      deliveryResponses: [buildDeliveryResponse({ outputId })],
    });
    const destination = buildDestination({
      outputId,
      outputType: DestinationTypeEnum.Slack,
      displayName,
    });
    const mocks = [mockListDestinations({ data: { destinations: [destination] } })];
    const { getByText, queryByText } = render(<Component alert={alert} />, { mocks });

    const loadingElement = queryByText('Loading...');
    expect(loadingElement).toBeInTheDocument();
    await waitForElementToBeRemoved(loadingElement);
    expect(getByText(displayName)).toBeInTheDocument();
  });
});
