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
  render,
  buildDestination,
  buildSendTestAlertInput,
  buildDeliveryResponse,
  fireClickAndMouseEvents,
  waitFor,
} from 'test-utils';
import { Wizard, WizardPanel } from 'Components/Wizard';
import { mockSendTestAlert } from 'Source/graphql/queries';
import DestinationTestPanel from './index';

const destination = buildDestination();
describe('DestinationTestPanel', () => {
  it('should show a success message for successful test-alert delivery', async () => {
    const deliveryResponse = buildDeliveryResponse({ statusCode: 200, success: true });
    const mocks = [
      mockSendTestAlert({
        variables: {
          input: buildSendTestAlertInput({ outputIds: [destination.outputId] }),
        },
        data: { sendTestAlert: [deliveryResponse] },
      }),
    ];
    const { getByText, container, getByAltText } = render(
      <Wizard initialData={{ destination }}>
        <Wizard.Step title="title">
          <WizardPanel>
            <DestinationTestPanel />
          </WizardPanel>
        </Wizard.Step>
      </Wizard>,
      { mocks }
    );

    expect(getByText('Everything looks good!')).toBeInTheDocument();
    const sendTestBtn = getByText('Send Test Alert');
    expect(container).toMatchSnapshot();
    await fireClickAndMouseEvents(sendTestBtn);
    await waitFor(() => {
      expect(getByAltText('Test Alert received')).toBeInTheDocument();
    });

    expect(container).toMatchSnapshot();
  });

  it('should show error details for a failing test-alert', async () => {
    const deliveryResponseMsg = 'This destination failed to pass the test';
    const deliveryResponse = buildDeliveryResponse({
      message: deliveryResponseMsg,
      statusCode: 400,
      success: false,
    });
    const mocks = [
      mockSendTestAlert({
        variables: {
          input: buildSendTestAlertInput({ outputIds: [destination.outputId] }),
        },
        data: { sendTestAlert: [deliveryResponse] },
      }),
    ];
    const { getByText, container, queryByAltText } = render(
      <Wizard initialData={{ destination }}>
        <Wizard.Step title="title">
          <WizardPanel>
            <DestinationTestPanel />
          </WizardPanel>
        </Wizard.Step>
      </Wizard>,
      { mocks }
    );

    expect(getByText('Everything looks good!')).toBeInTheDocument();
    const sendTestBtn = getByText('Send Test Alert');
    await fireClickAndMouseEvents(sendTestBtn);
    await waitFor(() => {
      expect(
        getByText(
          'Something went wrong and the destination you have configured did not receive the test alert. Please update your destination settings and try again.'
        )
      ).toBeInTheDocument();
      expect(getByText('Dispatched at')).toBeInTheDocument();

      expect(getByText('Status Code')).toBeInTheDocument();
      expect(getByText(deliveryResponseMsg)).toBeInTheDocument();
      expect(getByText('400')).toBeInTheDocument();
    });

    expect(queryByAltText('Test Alert received')).not.toBeInTheDocument();

    expect(container).toMatchSnapshot();
  });
});
