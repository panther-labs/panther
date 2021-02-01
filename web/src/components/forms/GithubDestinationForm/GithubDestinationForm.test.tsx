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
  waitFor,
  waitMs,
  buildGithubConfigInput,
  fireClickAndMouseEvents,
} from 'test-utils';
import { AlertTypesEnum, SeverityEnum } from 'Generated/schema';
import GithubDestinationForm from './index';

const emptyInitialValues = {
  outputId: null,
  displayName: '',
  defaultForSeverity: [],
  alertTypes: [],
  outputConfig: {
    github: {
      token: '',
      repoName: '',
    },
  },
};

const displayName = 'Github';
const severity = SeverityEnum.Critical;

const initialValues = {
  outputId: '123',
  displayName,
  outputConfig: {
    github: {
      token: '123',
      repoName: 'repo-name',
    },
  },
  defaultForSeverity: [severity],
  alertTypes: [AlertTypesEnum.Rule, AlertTypesEnum.RuleError, AlertTypesEnum.Policy],
};

describe('GithubDestinationForm', () => {
  it('renders the correct fields', () => {
    const { getByLabelText, getByText, getAllByLabelText } = render(
      <GithubDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const repoNameField = getByLabelText('Repository name');
    const tokenField = getByLabelText('Token');
    const submitButton = getByText('Add Destination');
    expect(displayNameField).toBeInTheDocument();
    expect(repoNameField).toBeInTheDocument();
    expect(tokenField).toBeInTheDocument();
    expect(getAllByLabelText('Severity')[0]).toBeInTheDocument();
    expect(getAllByLabelText('Alert Types')[0]).toBeInTheDocument();

    expect(submitButton).toHaveAttribute('disabled');
  });

  it('has proper validation', async () => {
    const { getByLabelText, getByText, getAllByLabelText } = render(
      <GithubDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const repoNameField = getByLabelText('Repository name');
    const tokenField = getByLabelText('Token');
    const submitButton = getByText('Add Destination');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(repoNameField, { target: { value: 'repo' } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(tokenField, { target: { value: 'someToken' } });
    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');
  });

  it('should trigger submit successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText, getAllByLabelText } = render(
      <GithubDestinationForm onSubmit={submitMockFunc} initialValues={emptyInitialValues} />
    );
    const githubInput = buildGithubConfigInput();
    const displayNameField = getByLabelText('* Display Name');
    const repoNameField = getByLabelText('Repository name');
    const tokenField = getByLabelText('Token');
    const submitButton = getByText('Add Destination');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    fireEvent.change(repoNameField, { target: { value: githubInput.repoName } });
    fireEvent.change(tokenField, { target: { value: githubInput.token } });
    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');

    fireEvent.click(submitButton);
    await waitFor(() => expect(submitMockFunc).toHaveBeenCalledTimes(1));
    expect(submitMockFunc).toHaveBeenCalledWith(
      {
        outputId: null,
        displayName,
        outputConfig: { github: githubInput },
        defaultForSeverity: [severity],
        alertTypes: [AlertTypesEnum.Rule],
      },
      expect.toBeObject()
    );
  });

  it('should edit Github Destination successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText } = render(
      <GithubDestinationForm onSubmit={submitMockFunc} initialValues={initialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const repoNameField = getByLabelText('Repository name');
    const tokenField = getByLabelText('Token');
    const submitButton = getByText('Update Destination');
    expect(displayNameField).toHaveValue(initialValues.displayName);
    expect(repoNameField).toHaveValue(initialValues.outputConfig.github.repoName);
    expect(tokenField).toHaveValue(initialValues.outputConfig.github.token);
    expect(submitButton).toHaveAttribute('disabled');

    const newDisplayName = 'New Github Name';
    fireEvent.change(displayNameField, { target: { value: newDisplayName } });
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');

    fireEvent.click(submitButton);
    await waitFor(() => expect(submitMockFunc).toHaveBeenCalledTimes(1));
    expect(submitMockFunc).toHaveBeenCalledWith(
      {
        outputId: initialValues.outputId,
        displayName: newDisplayName,
        outputConfig: initialValues.outputConfig,
        defaultForSeverity: initialValues.defaultForSeverity,
        alertTypes: initialValues.alertTypes,
      },
      expect.toBeObject()
    );
  });
});
