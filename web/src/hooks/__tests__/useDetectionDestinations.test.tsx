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

import { buildDestination, buildRuleSummary, render, waitForElementToBeRemoved } from 'test-utils';
import useDetectionDestinations from 'Hooks/useDetectionDestinations';
import { mockListDestinations } from 'Source/graphql/queries';
import { DestinationTypeEnum, SeverityEnum } from 'Generated/schema';
import React from 'react';

const Component = ({ rule }) => {
  const { loading, detectionDestinations } = useDetectionDestinations({ detection: rule });
  return (
    <div>
      {loading ? (
        <div aria-label="Loading">Loading...</div>
      ) : (
        detectionDestinations.map(dest => {
          return <div key={dest.outputId}>{dest.displayName}</div>;
        })
      )}
    </div>
  );
};

describe('useDetectionDestinations hook tests', () => {
  it('should display loading & display destination name when rules has destination override', async () => {
    const outputId = 'destination-of-alert';
    const displayName = 'Slack Destination';
    const rule = buildRuleSummary({
      outputIds: [outputId],
    });
    const destination = buildDestination({
      outputId,
      outputType: DestinationTypeEnum.Slack,
      displayName,
    });
    const mocks = [mockListDestinations({ data: { destinations: [destination] } })];
    const { queryByText } = render(<Component rule={rule} />, { mocks });

    const loadingElement = queryByText('Loading...');
    expect(loadingElement).toBeInTheDocument();
    await waitForElementToBeRemoved(loadingElement);
    expect(queryByText(displayName)).toBeInTheDocument();
  });

  it('should display loading & display destination for severity when rules has no destination override', async () => {
    const outputId = 'destination-of-alert';
    const displayName = 'Slack Destination';
    const rule = buildRuleSummary({
      outputIds: [],
      severity: SeverityEnum.High,
    });
    const destination = buildDestination({
      outputId,
      outputType: DestinationTypeEnum.Slack,
      displayName,
      defaultForSeverity: [SeverityEnum.Info, SeverityEnum.High],
    });
    const mocks = [mockListDestinations({ data: { destinations: [destination] } })];
    const { queryByText } = render(<Component rule={rule} />, { mocks });

    const loadingElement = queryByText('Loading...');
    expect(loadingElement).toBeInTheDocument();
    await waitForElementToBeRemoved(loadingElement);
    expect(queryByText(displayName)).toBeInTheDocument();
  });

  it("should display loading but no destination if there isn't a default destination for rule severity", async () => {
    const outputId = 'destination-of-alert';
    const displayName = 'Slack Destination';
    const rule = buildRuleSummary({
      outputIds: [],
      severity: SeverityEnum.Info,
    });
    const destination = buildDestination({
      outputId,
      outputType: DestinationTypeEnum.Slack,
      displayName,
      defaultForSeverity: [SeverityEnum.Critical, SeverityEnum.High],
    });
    const mocks = [mockListDestinations({ data: { destinations: [destination] } })];
    const { queryByText } = render(<Component rule={rule} />, { mocks });

    const loadingElement = queryByText('Loading...');
    expect(loadingElement).toBeInTheDocument();
    await waitForElementToBeRemoved(loadingElement);
    expect(queryByText(displayName)).not.toBeInTheDocument();
  });
});
