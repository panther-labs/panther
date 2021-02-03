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
import { render, fireEvent, waitFor, fireClickAndMouseEvents, buildRule, waitMs } from 'test-utils';
import urls from 'Source/urls';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { mockListAvailableLogTypes } from 'Source/graphql/queries';
import { GraphQLError } from 'graphql';
import { mockCreateRule } from './graphql/createRule.generated';
import CreateRule, { initialValues } from './CreateRule';

jest.mock('Helpers/analytics');

describe('CreateRule', () => {
  it('renders the initial tabs and fields', async () => {
    const { getByText, getByLabelText, getByAriaLabel } = render(<CreateRule />);

    // Fields
    expect(getByText('Enabled')).toBeInTheDocument();
    expect(getByText('Severity')).toBeInTheDocument();
    expect(getByLabelText('Display Name')).toBeInTheDocument();
    expect(getByLabelText('Rule ID')).toBeInTheDocument();
    expect(getByLabelText('Description')).toBeInTheDocument();
    expect(getByLabelText('Runbook')).toBeInTheDocument();
    expect(getByLabelText('Reference')).toBeInTheDocument();
    expect(getByText('Log Types')).toBeInTheDocument();
    expect(getByText('Custom Tags')).toBeInTheDocument();
    expect(getByText('Destination Overrides')).toBeInTheDocument();

    // Helper text
    expect(getByText('Required')).toBeInTheDocument();
    expect(getByText('Optional')).toBeInTheDocument();

    // Tabs
    expect(getByText('Rule Settings')).toBeInTheDocument();
    expect(getByText('Functions & Tests')).toBeInTheDocument();

    // Buttons
    expect(getByText('Save')).toBeInTheDocument();
    expect(getByAriaLabel('Cancel Rule editing')).toBeInTheDocument();
  });

  it('renders the function and tests tab', async () => {
    const { getByText, getByAriaLabel } = render(<CreateRule />);

    // Fields
    fireEvent.click(getByText('Functions & Tests'));

    await waitFor(() => {
      expect(getByText('Rule Function')).toBeInTheDocument();
    });

    fireEvent.click(getByText('Create your first test'));
    expect(getByText('Test event should trigger an alert')).toBeInTheDocument();

    expect(getByAriaLabel('Toggle Editor visibility')).toBeInTheDocument();
    expect(getByAriaLabel('Toggle Tests visibility')).toBeInTheDocument();
    expect(getByAriaLabel('Create test')).toBeInTheDocument();
  });

  it('can successfully create a rule', async () => {
    const logType = 'AWS.VPC';
    const rule = buildRule({ logTypes: [logType] });
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [logType],
          },
        },
      }),
      mockCreateRule({
        variables: {
          input: {
            ...initialValues,
            id: rule.id,
            severity: rule.severity,
            logTypes: rule.logTypes,
          },
        },
        data: { addRule: rule },
      }),
    ];
    const { getByText, findByText, getByLabelText, history, getAllByLabelText } = render(
      <CreateRule />,
      {
        mocks,
      }
    );

    fireEvent.change(getByLabelText('Rule ID'), { target: { value: rule.id } });

    const severityInput = getAllByLabelText('Severity')[0];
    fireClickAndMouseEvents(severityInput);
    fireClickAndMouseEvents(getByText(new RegExp(rule.severity, 'i')));

    const logTypeInput = getAllByLabelText('Log Types')[0];
    fireClickAndMouseEvents(logTypeInput);
    fireEvent.change(logTypeInput, { target: { value: logType } });
    fireClickAndMouseEvents(await findByText(logType));

    await waitMs(1);

    fireEvent.click(getByText('Save'));

    await waitFor(() =>
      expect(history.location.pathname).toEqual(urls.logAnalysis.rules.details(rule.id))
    );

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedRule,
      src: SrcEnum.Rules,
    });
  });

  it('can handle policy creation failures', async () => {
    const logType = 'AWS.VPC';
    const rule = buildRule({ logTypes: [logType] });
    const mocks = [
      mockListAvailableLogTypes({
        data: {
          listAvailableLogTypes: {
            logTypes: [logType],
          },
        },
      }),
      mockCreateRule({
        variables: {
          input: {
            ...initialValues,
            id: rule.id,
            severity: rule.severity,
            logTypes: rule.logTypes,
          },
        },
        data: null,
        errors: [new GraphQLError('Fake Error')],
      }),
    ];
    const { getByText, findByText, getByLabelText, history, getAllByLabelText } = render(
      <CreateRule />,
      {
        mocks,
      }
    );

    fireEvent.change(getByLabelText('Rule ID'), { target: { value: rule.id } });

    const severityInput = getAllByLabelText('Severity')[0];
    fireClickAndMouseEvents(severityInput);
    fireClickAndMouseEvents(getByText(new RegExp(rule.severity, 'i')));

    const logTypeInput = getAllByLabelText('Log Types')[0];
    fireClickAndMouseEvents(logTypeInput);
    fireEvent.change(logTypeInput, { target: { value: logType } });
    fireClickAndMouseEvents(await findByText(logType));

    await waitMs(1);

    fireEvent.click(getByText('Save'));

    expect(await findByText('Fake Error')).toBeInTheDocument();
    expect(history.location.pathname).toEqual('/');

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToAddRule,
      src: SrcEnum.Rules,
    });
  });
});
