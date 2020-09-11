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
import { buildAlertDetails, buildRuleDetails, render } from 'test-utils';
import urls from 'Source/urls';
import { DEFAULT_LARGE_PAGE_SIZE } from 'Source/constants';
import { Route } from 'react-router-dom';
import { mockAlertDetails } from './graphql/alertDetails.generated';
import { mockRuleTeaser } from './graphql/ruleTeaser.generated';
import AlertDetails from './AlertDetails';

it('renders the correct tab based on a URL param', async () => {
  const alert = buildAlertDetails({ events: ['"{}"', '"{}"'] });
  const rule = buildRuleDetails();

  const mocks = [
    mockAlertDetails({
      variables: {
        input: {
          alertId: alert.alertId,
          eventsPageSize: DEFAULT_LARGE_PAGE_SIZE,
        },
      },
      data: { alert },
    }),
    mockRuleTeaser({
      variables: {
        input: {
          ruleId: alert.ruleId,
        },
      },
      data: { rule },
    }),
  ];

  // render initially with the "details" section
  const { findByText, getByText, queryByText, unmount } = render(
    <Route exact path={urls.logAnalysis.alerts.details(':id')}>
      <AlertDetails />
    </Route>,
    {
      mocks,
      initialRoute: `${urls.logAnalysis.alerts.details(alert.alertId)}?section=details`,
    }
  );

  // expect to see all the data, but not to see the "Triggered events
  expect(await findByText('Rule')).toBeInTheDocument();
  expect(getByText('Rule').closest('[hidden]')).not.toBeInTheDocument();
  expect(getByText('Rule Threshold')).toBeInTheDocument();
  expect(getByText('Deduplication Period')).toBeInTheDocument();
  expect(getByText('Deduplication String')).toBeInTheDocument();
  expect(queryByText('Triggered Events')).not.toBeInTheDocument();

  // unmount everything
  unmount();

  // remount with the events section
  const { findByText: _findByText, getByText: _getByText } = render(
    <Route exact path={urls.logAnalysis.alerts.details(':id')}>
      <AlertDetails />
    </Route>,
    {
      mocks,
      initialRoute: `${urls.logAnalysis.alerts.details(alert.alertId)}?section=events`,
    }
  );

  // expect to see all the data as "hidden" (since the details tab is always loaded (i.e. no lazy load)
  // and the "Triggered events" being shown
  expect((await _findByText('Rule')).closest('[hidden]')).toBeInTheDocument();
  expect(_getByText('Rule Threshold').closest('[hidden]')).toBeInTheDocument();
  expect(_getByText('Deduplication Period').closest('[hidden]')).toBeInTheDocument();
  expect(_getByText('Deduplication String').closest('[hidden]')).toBeInTheDocument();
  expect(await _findByText('Triggered Events')).toBeInTheDocument();
  expect(getByText('Triggered Events').closest('[hidden]')).not.toBeInTheDocument();
});
