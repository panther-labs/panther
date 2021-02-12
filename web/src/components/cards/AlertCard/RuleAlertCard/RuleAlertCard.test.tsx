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
  buildAlertSummaryRuleInfo,
  buildDeliveryResponse,
  buildDestination,
  render,
  waitForElementToBeRemoved,
} from 'test-utils';
import React from 'react';
import {
  AlertStatusesEnum,
  AlertSummaryRuleInfo,
  DestinationTypeEnum,
  SeverityEnum,
} from 'Generated/schema';
import urls from 'Source/urls';
import { mockListDestinations } from 'Source/graphql/queries';
import RuleAlertCard from './index';

describe('RuleAlertCard', () => {
  it('should match snapshot', async () => {
    const alert = buildAlertSummary();

    const { container } = render(<RuleAlertCard alert={alert} />);

    expect(container).toMatchSnapshot();
  });

  it('displays the correct Alert data in the card', async () => {
    const alert = buildAlertSummary({
      detection: buildAlertSummaryRuleInfo({
        logTypes: ['alpha', 'beta'],
      }),
    });
    const detectionData = alert.detection as AlertSummaryRuleInfo;

    const { getByText, getByAriaLabel } = render(<RuleAlertCard alert={alert} />);

    expect(getByText(alert.title)).toBeInTheDocument();
    expect(getByAriaLabel(`Link to rule ${detectionData.ruleId}`)).toBeInTheDocument();
    expect(getByText('Events')).toBeInTheDocument();
    expect(getByAriaLabel(`Creation time for ${alert.alertId}`)).toBeInTheDocument();
    expect(getByText(SeverityEnum.Medium)).toBeInTheDocument();
    expect(getByText(AlertStatusesEnum.Triaged)).toBeInTheDocument();
    expect(getByAriaLabel('Change Alert Status')).toBeInTheDocument();

    detectionData.logTypes.forEach(logType => {
      expect(getByText(logType)).toBeInTheDocument();
    });
  });

  it('should not display link to Rule', async () => {
    const alert = buildAlertSummary();
    const detectionData = alert.detection as AlertSummaryRuleInfo;

    const { queryByText, queryByAriaLabel } = render(
      <RuleAlertCard alert={alert} hideRuleButton />
    );

    expect(queryByText(alert.title)).toBeInTheDocument();
    expect(queryByAriaLabel(`Link to rule ${detectionData.ruleId}`)).not.toBeInTheDocument();
  });

  it('should check links are valid', async () => {
    const alert = buildAlertSummary();
    const detectionData = alert.detection as AlertSummaryRuleInfo;

    const { getByAriaLabel } = render(<RuleAlertCard alert={alert} />);

    expect(getByAriaLabel('Link to Alert')).toHaveAttribute(
      'href',
      urls.logAnalysis.alerts.details(alert.alertId)
    );
    expect(getByAriaLabel(`Link to rule ${detectionData.ruleId}`)).toHaveAttribute(
      'href',
      urls.logAnalysis.rules.details(detectionData.ruleId)
    );
  });

  it('should render alert destinations logos', async () => {
    const outputId = 'destination-of-alert';
    const alert = buildAlertSummary({
      deliveryResponses: [buildDeliveryResponse({ outputId })],
    });
    const destination = buildDestination({ outputId, outputType: DestinationTypeEnum.Slack });
    const mocks = [mockListDestinations({ data: { destinations: [destination] } })];

    const { getByAriaLabel, getByAltText } = render(<RuleAlertCard alert={alert} />, {
      mocks,
    });
    const loadingInterfaceElement = getByAriaLabel('Loading...');
    expect(loadingInterfaceElement).toBeInTheDocument();
    await waitForElementToBeRemoved(loadingInterfaceElement);
    expect(getByAltText(`${destination.outputType} logo`)).toBeInTheDocument();
  });

  it('should render message that destination delivery is failing', async () => {
    const outputId = 'destination-of-alert';
    const alert = buildAlertSummary({
      deliveryResponses: [buildDeliveryResponse({ outputId, success: false })],
    });
    const destination = buildDestination({ outputId, outputType: DestinationTypeEnum.Slack });
    const mocks = [mockListDestinations({ data: { destinations: [destination] } })];

    const { getByAriaLabel, getByAltText } = render(<RuleAlertCard alert={alert} />, {
      mocks,
    });
    const loadingInterfaceElement = getByAriaLabel('Loading...');
    expect(loadingInterfaceElement).toBeInTheDocument();
    await waitForElementToBeRemoved(loadingInterfaceElement);
    expect(getByAltText(`${destination.outputType} logo`)).toBeInTheDocument();
    expect(getByAriaLabel('Destination delivery failure')).toBeInTheDocument();
  });
});
