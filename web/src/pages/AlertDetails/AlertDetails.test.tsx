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
  buildAlertDetails,
  buildAlertDetailsRuleInfo,
  buildAlertSummary,
  buildAlertSummaryPolicyInfo,
  buildDeliveryResponse,
  buildDestination,
  buildPolicy,
  buildRule,
  fireEvent,
  render,
  within,
} from 'test-utils';
import urls from 'Source/urls';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { AlertDetailsRuleInfo, AlertSummaryPolicyInfo, AlertTypesEnum } from 'Generated/schema';
import { Route } from 'react-router-dom';
import { mockListComplianceSourceNames, mockListDestinations } from 'Source/graphql/queries';
import { mockAlertDetails } from './graphql/alertDetails.generated';
import { mockGetRuleSummary } from './RuleAlertDetails/graphql/getRuleSummary.generated';
import { mockGetPolicySummary } from './PolicyAlertDetails/graphql/getPolicySummary.generated';
import { mockRetryAlertDelivery } from './common/AlertDeliverySection/graphql/retryAlertDelivery.generated';
import AlertDetails from './AlertDetails';

describe('AlertDetails', () => {
  describe('Rule-based', () => {
    it('renders the correct tab based on a URL param', async () => {
      const destination = buildDestination();
      const alert = buildAlertDetails({
        detection: buildAlertDetailsRuleInfo({
          events: ['"{}"', '"{}"'],
        }),
        deliveryResponses: [buildDeliveryResponse({ outputId: destination.outputId })],
      });
      const rule = buildRule();

      const mocks = [
        mockListDestinations({ data: { destinations: [destination] } }),
        mockAlertDetails({
          variables: {
            input: {
              alertId: alert.alertId,
              eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
            },
          },
          data: { alert },
        }),
        mockGetRuleSummary({
          variables: {
            input: {
              id: (alert.detection as AlertDetailsRuleInfo).ruleId,
            },
          },
          data: { rule },
        }),
      ];

      // render initially with the "details" section
      const { getByText, getByTestId, findByTestId } = render(
        <Route exact path={urls.logAnalysis.alerts.details(':id')}>
          <AlertDetails />
        </Route>,
        {
          mocks,
          initialRoute: `${urls.logAnalysis.alerts.details(alert.alertId)}?section=details`,
        }
      );

      // expect to see all the data, but not to see the "Triggered events
      const detailsTabPanel = await findByTestId('alert-details-tabpanel');
      expect(detailsTabPanel).toBeInTheDocument();
      expect(getByText('Rule Threshold')).toBeInTheDocument();
      expect(getByText('Deduplication Period')).toBeInTheDocument();
      expect(getByText('Deduplication String')).toBeInTheDocument();
      expect(getByTestId('alert-details-tabpanel')).toBeVisible();

      // Expect the Triggered Events tab to be hidden & lazy loaded
      const eventsTabPanel = getByTestId('alert-events-tabpanel');
      expect(eventsTabPanel).not.toBeVisible();
      expect(eventsTabPanel).toBeEmptyDOMElement();
    });

    it('correctly lazy loads event tab', async () => {
      const destination = buildDestination();
      const alert = buildAlertDetails({
        detection: buildAlertDetailsRuleInfo({
          events: ['"{}"', '"{}"'],
        }),
        deliveryResponses: [buildDeliveryResponse({ outputId: destination.outputId })],
      });
      const rule = buildRule();

      const mocks = [
        mockListDestinations({ data: { destinations: [destination] } }),
        mockAlertDetails({
          variables: {
            input: {
              alertId: alert.alertId,
              eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
            },
          },
          data: { alert },
        }),
        mockGetRuleSummary({
          variables: {
            input: {
              id: (alert.detection as AlertDetailsRuleInfo).ruleId,
            },
          },
          data: { rule },
        }),
      ];

      // remount with the events section
      const { findByTestId, getByTestId } = render(
        <Route exact path={urls.logAnalysis.alerts.details(':id')}>
          <AlertDetails />
        </Route>,
        {
          mocks,
          initialRoute: `${urls.logAnalysis.alerts.details(alert.alertId)}?section=events`,
        }
      );

      // expect to see all the data as "hidden" (since the details tab is always loaded i.e. no lazy load)
      const detailsTabPanel = await findByTestId('alert-details-tabpanel');
      expect(detailsTabPanel).toBeInTheDocument();
      expect(detailsTabPanel).not.toBeVisible();
      expect(detailsTabPanel).not.toBeEmptyDOMElement();

      // Expect the triggered events to be visible and NOT hidden
      const eventsTabPanel = getByTestId('alert-events-tabpanel');
      expect(eventsTabPanel).toBeVisible();
      expect(eventsTabPanel).not.toBeEmptyDOMElement();
    });

    it('shows destination information in the details tab', async () => {
      const destination = buildDestination();
      const alert = buildAlertDetails({
        detection: buildAlertDetailsRuleInfo({
          events: ['"{}"', '"{}"'],
        }),
        deliveryResponses: [buildDeliveryResponse({ outputId: destination.outputId })],
      });
      const rule = buildRule();

      const mocks = [
        mockListDestinations({ data: { destinations: [destination] } }),
        mockAlertDetails({
          variables: {
            input: {
              alertId: alert.alertId,
              eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
            },
          },
          data: { alert },
        }),
        mockGetRuleSummary({
          variables: {
            input: {
              id: (alert.detection as AlertDetailsRuleInfo).ruleId,
            },
          },
          data: { rule },
        }),
      ];

      // render initially with the "details" section
      const { findByTestId } = render(
        <Route exact path={urls.logAnalysis.alerts.details(':id')}>
          <AlertDetails />
        </Route>,
        {
          mocks,
          initialRoute: `${urls.logAnalysis.alerts.details(alert.alertId)}?section=details`,
        }
      );

      // expect to see all the data, but not to see the "Triggered events

      const detailsTabPanel = await findByTestId('alert-details-tabpanel');
      const { getByText: getByTextWithinDetailsTabPanel } = within(detailsTabPanel);
      expect(getByTextWithinDetailsTabPanel(destination.displayName)).toBeInTheDocument();
    });

    it('correctly updates the delivery status on a delivery retry', async () => {
      const rule = buildRule();
      const destination = buildDestination();

      const previousDeliveryResponse = buildDeliveryResponse({
        success: false,
        outputId: destination.outputId,
      });
      const updatedDeliveryResponse = { ...previousDeliveryResponse, success: true };

      const alert = buildAlertDetails({
        deliveryResponses: [previousDeliveryResponse],
      });
      const updatedAlert = buildAlertSummary({
        alertId: alert.alertId,
        deliveryResponses: [previousDeliveryResponse, updatedDeliveryResponse],
      });

      const mocks = [
        mockListDestinations({ data: { destinations: [destination] } }),
        mockAlertDetails({
          variables: {
            input: {
              alertId: alert.alertId,
              eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
            },
          },
          data: { alert },
        }),
        mockGetRuleSummary({
          variables: {
            input: {
              id: (alert.detection as AlertDetailsRuleInfo).ruleId,
            },
          },
          data: { rule },
        }),
        mockRetryAlertDelivery({
          variables: {
            input: {
              alertId: alert.alertId,
              outputIds: [previousDeliveryResponse.outputId],
            },
          },
          data: {
            deliverAlert: updatedAlert,
          },
        }),
      ];

      const { queryByText, findByText, getByAriaLabel } = render(
        <Route exact path={urls.logAnalysis.alerts.details(':id')}>
          <AlertDetails />
        </Route>,
        { mocks, initialRoute: `${urls.logAnalysis.alerts.details(alert.alertId)}` }
      );

      expect(await findByText('Alert delivery failed')).toBeInTheDocument();

      fireEvent.click(queryByText('Show History'));
      fireEvent.click(getByAriaLabel('Retry delivery'));

      // Expect section banner to change
      expect(await findByText('Alert was delivered successfully')).toBeInTheDocument();
      // Expect to see snackbar
      expect(queryByText('Successfully delivered alert')).toBeInTheDocument();
    });
  });

  describe('Policy-based', () => {
    it('renders the necessary policy information', async () => {
      const destination = buildDestination();
      const policy = buildPolicy();
      const alert = buildAlertDetails({
        type: AlertTypesEnum.Policy,
        detection: buildAlertSummaryPolicyInfo({ policyId: policy.id }),
        deliveryResponses: [buildDeliveryResponse({ outputId: destination.outputId })],
      });
      const detectionData = alert.detection as AlertSummaryPolicyInfo;

      const mocks = [
        mockListComplianceSourceNames({
          data: {
            listComplianceIntegrations: [
              {
                integrationId: detectionData.policySourceId,
                integrationLabel: 'Test Source',
              },
            ],
          },
        }),
        mockListDestinations({ data: { destinations: [destination] } }),
        mockAlertDetails({
          variables: {
            input: {
              alertId: alert.alertId,
              eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
            },
          },
          data: { alert },
        }),
        mockGetPolicySummary({
          variables: {
            input: {
              id: policy.id,
            },
          },
          data: { policy },
        }),
      ];

      // render initially with the "details" section
      const { getByText, findByText } = render(
        <Route exact path={urls.logAnalysis.alerts.details(':id')}>
          <AlertDetails />
        </Route>,
        {
          mocks,
          initialRoute: urls.logAnalysis.alerts.details(alert.alertId),
        }
      );

      // expect to see all the data, but not to see the "Triggered events
      expect(await findByText(policy.displayName)).toBeInTheDocument();
      expect(await findByText('Test Source')).toBeInTheDocument();
      expect(getByText('Policy Fail')).toBeInTheDocument();
      expect(getByText(policy.reference)).toBeInTheDocument();
      expect(getByText(policy.runbook)).toBeInTheDocument();
      detectionData.resourceTypes.forEach(resourceType => {
        expect(getByText(resourceType)).toBeInTheDocument();
      });
    });
  });
});
