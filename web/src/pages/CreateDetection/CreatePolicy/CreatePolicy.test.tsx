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
  fireEvent,
  waitForElementToBeRemoved,
  waitFor,
  fireClickAndMouseEvents,
  buildPolicy,
  waitMs,
} from 'test-utils';
import { mockListRemediations } from 'Components/forms/PolicyForm/PolicyFormAutoRemediationSection';
import urls from 'Source/urls';
import { EventEnum, SrcEnum, trackError, TrackErrorEnum, trackEvent } from 'Helpers/analytics';
import { GraphQLError } from 'graphql';
import CreatePolicy, { initialValues } from './CreatePolicy';
import { mockCreatePolicy } from './graphql/createPolicy.generated';

jest.mock('Helpers/analytics');

describe('CreatePolicy', () => {
  it('renders the initial tabs and fields', async () => {
    const { getByText, getByLabelText, getByAriaLabel } = render(<CreatePolicy />);

    // Fields
    expect(getByText('Enabled')).toBeInTheDocument();
    expect(getByText('Severity')).toBeInTheDocument();
    expect(getByLabelText('Display Name')).toBeInTheDocument();
    expect(getByLabelText('Policy ID')).toBeInTheDocument();
    expect(getByLabelText('Description')).toBeInTheDocument();
    expect(getByLabelText('Runbook')).toBeInTheDocument();
    expect(getByLabelText('Reference')).toBeInTheDocument();
    expect(getByText('Resource Types')).toBeInTheDocument();
    expect(getByText('Custom Tags')).toBeInTheDocument();
    expect(getByText('Ignore Patterns')).toBeInTheDocument();
    expect(getByText('Destination Overrides')).toBeInTheDocument();

    // Helper text
    expect(getByText('Required')).toBeInTheDocument();
    expect(getByText('Optional')).toBeInTheDocument();

    // Tabs
    expect(getByText('Policy Settings')).toBeInTheDocument();
    expect(getByText('Functions & Tests')).toBeInTheDocument();
    expect(getByText('Auto Remediation')).toBeInTheDocument();

    // Buttons
    expect(getByText('Save')).toBeInTheDocument();
    expect(getByAriaLabel('Cancel Policy editing')).toBeInTheDocument();
  });

  it('renders the function and tests tab', async () => {
    const { getByText, getByAriaLabel } = render(<CreatePolicy />);

    // Fields
    fireEvent.click(getByText('Functions & Tests'));

    await waitFor(() => {
      expect(getByText('Policy Function')).toBeInTheDocument();
    });

    fireEvent.click(getByText('Create your first test'));
    expect(getByText('Test resource should be compliant')).toBeInTheDocument();

    expect(getByAriaLabel('Toggle Editor visibility')).toBeInTheDocument();
    expect(getByAriaLabel('Toggle Tests visibility')).toBeInTheDocument();
    expect(getByAriaLabel('Create test')).toBeInTheDocument();
  });

  it('renders the Auto Remediation tab', async () => {
    const mocks = [
      mockListRemediations({
        data: {
          remediations:
            '{"AWS.EC2.TerminateInstance":{},"AWS.IAM.DeleteInactiveAccessKeys":{},"AWS.RDS.DisableSnapshotPublicAccess":{},"AWS.DDB.EncryptTable":{},"AWS.EC2.StopInstance":{}}',
        },
      }),
    ];
    const { getAllByLabelText, getByText, getByAriaLabel } = render(<CreatePolicy />, {
      mocks,
    });

    // Fields
    fireEvent.click(getByText('Auto Remediation'));

    const remediationLoading = getByAriaLabel('Loading...');
    expect(remediationLoading).toBeTruthy();
    await waitForElementToBeRemoved(remediationLoading);

    await waitFor(() => {
      expect(getByText('Remediation')).toBeInTheDocument();
    });

    const remedationField = getAllByLabelText('Remediation')[0];
    expect(remedationField).toHaveValue('(No remediation)');

    // The combobox is searchable thus we need to focus first
    await fireEvent.focus(remedationField);
    await fireClickAndMouseEvents(remedationField);
    await fireClickAndMouseEvents(getByText('AWS.IAM.DeleteInactiveAccessKeys'));

    await waitFor(() => {
      expect(getByAriaLabel('Auto Remediation Parameters')).toBeInTheDocument();
    });
  });

  it('can successfully create a policy', async () => {
    const resourceType = 'AWS.EC2.VPC';
    const policy = buildPolicy({ resourceTypes: [resourceType] });
    const mocks = [
      mockCreatePolicy({
        variables: {
          input: {
            ...initialValues,
            id: policy.id,
            severity: policy.severity,
            resourceTypes: policy.resourceTypes,
          },
        },
        data: { addPolicy: policy },
      }),
    ];
    const { getByText, getByLabelText, history, getAllByLabelText } = render(<CreatePolicy />, {
      mocks,
    });

    fireEvent.change(getByLabelText('Policy ID'), { target: { value: policy.id } });

    const severityInput = getAllByLabelText('Severity')[0];
    fireClickAndMouseEvents(severityInput);
    fireClickAndMouseEvents(getByText(new RegExp(policy.severity, 'i')));

    const resourceTypeInput = getAllByLabelText('Resource Types')[0];
    fireClickAndMouseEvents(resourceTypeInput);
    fireEvent.change(resourceTypeInput, { target: { value: resourceType } });
    fireClickAndMouseEvents(getByText(resourceType));

    await waitMs(1);

    fireEvent.click(getByText('Save'));

    await waitFor(() =>
      expect(history.location.pathname).toEqual(urls.compliance.policies.details(policy.id))
    );

    // Expect analytics to have been called
    expect(trackEvent).toHaveBeenCalledWith({
      event: EventEnum.AddedPolicy,
      src: SrcEnum.Detections,
    });
  });

  it('can handle policy creation failures', async () => {
    const resourceType = 'AWS.EC2.VPC';
    const policy = buildPolicy({ resourceTypes: [resourceType] });
    const mocks = [
      mockCreatePolicy({
        variables: {
          input: {
            ...initialValues,
            id: policy.id,
            severity: policy.severity,
            resourceTypes: policy.resourceTypes,
          },
        },
        data: null,
        errors: [new GraphQLError('Fake Error')],
      }),
    ];
    const { findByText, getByText, getByLabelText, history, getAllByLabelText } = render(
      <CreatePolicy />,
      {
        mocks,
      }
    );

    fireEvent.change(getByLabelText('Policy ID'), { target: { value: policy.id } });

    const severityInput = getAllByLabelText('Severity')[0];
    fireClickAndMouseEvents(severityInput);
    fireClickAndMouseEvents(getByText(new RegExp(policy.severity, 'i')));

    const resourceTypeInput = getAllByLabelText('Resource Types')[0];
    fireClickAndMouseEvents(resourceTypeInput);
    fireEvent.change(resourceTypeInput, { target: { value: resourceType } });
    fireClickAndMouseEvents(getByText(resourceType));

    await waitMs(1);

    fireEvent.click(getByText('Save'));

    expect(await findByText('Fake Error')).toBeInTheDocument();
    expect(history.location.pathname).toEqual('/');

    // Expect analytics to have been called
    expect(trackError).toHaveBeenCalledWith({
      event: TrackErrorEnum.FailedToAddPolicy,
      src: SrcEnum.Detections,
    });
  });
});
