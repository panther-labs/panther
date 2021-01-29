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

import { buildDestination, buildPagerDutyConfig, render } from 'test-utils';
import React from 'react';
import { DestinationFull } from 'Source/graphql/fragments/DestinationFull.generated';
import { DestinationTypeEnum } from 'Generated/schema';
import { alertTypeToString } from 'Helpers/utils';
import { PagerDutyDestinationCard } from '../index';

describe('PagerDutyDestinationCard', () => {
  it('displays PagerDuty data in the card', async () => {
    const pageDutyDestination = buildDestination({
      outputType: DestinationTypeEnum.Pagerduty,
      outputConfig: { pagerDuty: buildPagerDutyConfig() },
    }) as DestinationFull;
    const { getByText, getByAriaLabel, getByAltText } = render(
      <PagerDutyDestinationCard destination={pageDutyDestination} />
    );

    expect(getByAltText(/Logo/i)).toBeInTheDocument();
    expect(getByAriaLabel(/Toggle Options/i)).toBeInTheDocument();
    expect(getByText(pageDutyDestination.displayName)).toBeInTheDocument();
    expect(
      getByText(pageDutyDestination.alertTypes.map(alertTypeToString).join(' ,'))
    ).toBeInTheDocument();
  });
});
