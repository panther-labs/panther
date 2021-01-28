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
  buildAsanaConfig,
  buildDestination,
  render,
  fireEvent,
  waitMs,
  buildDeliveryResponse,
  fireClickAndMouseEvents,
} from 'test-utils';
import React from 'react';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { DestinationTypeEnum } from 'Generated/schema';
import { DESTINATIONS } from 'Source/constants';
import { mockSendTestAlert } from 'Source/graphql/queries';
import DestinationCard from '../DestinationCard';

const { logo } = DESTINATIONS[DestinationTypeEnum.Asana];

describe('Generic Destination Card', () => {
  it('should match snapshot', async () => {
    const destination = buildDestination({
      outputType: DestinationTypeEnum.Asana,
      outputConfig: { asana: buildAsanaConfig() },
    }) as DestinationFull;
    const { container } = render(
      <DestinationCard destination={destination} logo={logo}>
        A children
      </DestinationCard>
    );

    expect(container).toMatchSnapshot();
  });

  it('should render card and toggle options', async () => {
    const destination = buildDestination({
      outputType: DestinationTypeEnum.Asana,
      outputConfig: { asana: buildAsanaConfig() },
    }) as DestinationFull;
    const { getByText, getByAriaLabel, getByAltText } = render(
      <DestinationCard destination={destination} logo={logo}>
        A required children
      </DestinationCard>
    );

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    const toggleBtn = getByAriaLabel(/Toggle Options/i);
    expect(toggleBtn).toBeInTheDocument();

    fireEvent.mouseDown(toggleBtn);
    await waitMs(1);
    expect(getByText('Send Test Alert')).toBeInTheDocument();
    expect(getByText('Delete')).toBeInTheDocument();
    expect(getByText('Edit')).toBeInTheDocument();
  });

  it('should send a test alert for destinations', async () => {
    const destination = buildDestination({
      outputType: DestinationTypeEnum.Asana,
      outputConfig: { asana: buildAsanaConfig() },
    }) as DestinationFull;
    const mocks = [
      mockSendTestAlert({
        variables: {
          input: {
            outputIds: [destination.outputId],
          },
        },
        data: {
          sendTestAlert: [buildDeliveryResponse({ success: true })],
        },
      }),
    ];
    const { findByText, getByAriaLabel, getByAltText } = render(
      <DestinationCard destination={destination} logo={logo}>
        A required children
      </DestinationCard>,
      { mocks }
    );

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    const toggleBtn = getByAriaLabel(/Toggle Options/i);
    expect(toggleBtn).toBeInTheDocument();

    fireClickAndMouseEvents(toggleBtn);
    fireClickAndMouseEvents(await findByText('Send Test Alert'));
    expect(
      await findByText(`Successfully sent test alert for: ${destination.displayName}`)
    ).toBeInTheDocument();
  });
});
