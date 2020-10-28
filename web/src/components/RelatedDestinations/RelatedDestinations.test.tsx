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

import { buildDestination, render } from 'test-utils';
import React from 'react';
import { DestinationTypeEnum } from 'Generated/schema';

import RelatedDestinations from './index';

const slackDest = buildDestination({
  outputId: '123',
  outputType: DestinationTypeEnum.Slack,
  displayName: 'Slack dest',
});
const pagerDutyDest = buildDestination({
  outputId: '234',
  outputType: DestinationTypeEnum.Pagerduty,
  displayName: 'Pagerduty Dest',
});

describe('RelatedDestination', () => {
  it('should display verbose destinations', async () => {
    const { queryByAltText, queryByText } = render(
      <RelatedDestinations destinations={[slackDest, pagerDutyDest]} loading={false} verbose />
    );
    expect(queryByAltText(`${slackDest.outputType} logo`)).toBeInTheDocument();
    expect(queryByAltText(`${pagerDutyDest.outputType} logo`)).toBeInTheDocument();
    expect(queryByText(slackDest.displayName)).toBeInTheDocument();
    expect(queryByText(pagerDutyDest.displayName)).toBeInTheDocument();
  });

  it('should display non-verbose destinations', async () => {
    const { queryByAltText, queryByText } = render(
      <RelatedDestinations destinations={[slackDest, pagerDutyDest]} loading={false} />
    );
    expect(queryByAltText(`${slackDest.outputType} logo`)).toBeInTheDocument();
    expect(queryByAltText(`${pagerDutyDest.outputType} logo`)).toBeInTheDocument();
    expect(queryByText(slackDest.displayName)).not.toBeInTheDocument();
    expect(queryByText(pagerDutyDest.displayName)).not.toBeInTheDocument();
  });

  it('should display loading spinner', async () => {
    const { queryByText, queryByAltText, queryByAriaLabel } = render(
      <RelatedDestinations destinations={[slackDest, pagerDutyDest]} loading={true} />
    );
    expect(queryByAriaLabel('Loading...')).toBeInTheDocument();
    expect(queryByAltText(`${slackDest.outputType} logo`)).not.toBeInTheDocument();
    expect(queryByAltText(`${pagerDutyDest.outputType} logo`)).not.toBeInTheDocument();
    expect(queryByText(slackDest.displayName)).not.toBeInTheDocument();
    expect(queryByText(pagerDutyDest.displayName)).not.toBeInTheDocument();
  });
});
