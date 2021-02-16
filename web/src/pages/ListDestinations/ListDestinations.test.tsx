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
import urls from 'Source/urls';
import { buildDestination, render, fireClickAndMouseEvents } from 'test-utils';
import { mockDeleteOutput } from 'Components/modals/DeleteDestinationModal';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { mockListDestinationsAndDefaults } from './graphql/listDestinationsAndDefaults.generated';
import ListDestinations from './ListDestinations';

const destinations = [
  buildDestination({ outputId: '1', displayName: 'First Destination' }),
  buildDestination({ outputId: '2', displayName: 'Second Destination' }),
] as DestinationFull[];

describe('ListDestinations', () => {
  it('renders a placeholder when no destinations are present', async () => {
    const mocks = [
      mockListDestinationsAndDefaults({
        data: {
          destinations: [],
        },
      }),
    ];

    const { findByText } = render(<ListDestinations />, { mocks });
    expect(await findByText('Help us reach you')).toBeInTheDocument();
    expect(await findByText('Add your first Destination')).toBeInTheDocument();
  });

  it('renders a list of Destinations when they exist', async () => {
    const mocks = [
      mockListDestinationsAndDefaults({
        data: {
          destinations,
        },
      }),
    ];

    const { findByText, findAllByText, findAllByAriaLabel } = render(<ListDestinations />, {
      mocks,
    });

    expect(await findByText('Add Destination')).toBeInTheDocument();
    expect(await findByText('First Destination')).toBeInTheDocument();
    expect(await findByText('Second Destination')).toBeInTheDocument();
    expect(await findAllByAriaLabel('Toggle Options')).toHaveLength(2);

    destinations[0].defaultForSeverity.map(async severity => {
      expect(await findAllByText(severity)).toHaveLength(destinations.length);
    });
  });

  it('allows editing of a destination', async () => {
    const mocks = [
      mockListDestinationsAndDefaults({
        data: {
          destinations,
        },
      }),
    ];

    const { findByText, findAllByAriaLabel } = render(<ListDestinations />, {
      mocks,
    });

    const options = await findAllByAriaLabel('Toggle Options');
    const promises = options.map(async (option, index) => {
      // open menu
      fireClickAndMouseEvents(option);

      // check edit button link
      const editButton = await findByText('Edit');
      expect(editButton.parentElement).toHaveAttribute(
        'href',
        urls.integrations.destinations.edit(destinations[index].outputId)
      );

      // close menu
      fireClickAndMouseEvents(option);
    });

    await Promise.all(promises);
  });

  it('can delete a destination', async () => {
    const mocks = [
      mockDeleteOutput({ data: { deleteDestination: true } }),
      mockListDestinationsAndDefaults({
        data: {
          destinations,
        },
      }),
    ];

    const { findByText, findAllByAriaLabel, getByText, queryByText } = render(
      <ListDestinations />,
      { mocks }
    );

    // Make sure that there are 2 destinations
    expect(await findByText('First Destination')).toBeInTheDocument();
    expect(await findByText('Second Destination')).toBeInTheDocument();
    const options = await findAllByAriaLabel('Toggle Options');
    const firstDestinationOptionsButton = options[0];

    // Open menu -> click delete -> click confirm on the modal that appears
    fireClickAndMouseEvents(firstDestinationOptionsButton);
    fireClickAndMouseEvents(getByText('Delete'));
    fireClickAndMouseEvents(getByText('Confirm'));

    // Expect too see  1 destination in the screen now
    expect(queryByText('First Destination')).not.toBeInTheDocument();
    expect(getByText('Second Destination')).toBeInTheDocument();
  });
});
