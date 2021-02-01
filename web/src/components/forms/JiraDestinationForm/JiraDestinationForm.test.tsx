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
  faker,
  buildJiraConfigInput,
  fireClickAndMouseEvents,
} from 'test-utils';
import { AlertTypesEnum, SeverityEnum } from 'Generated/schema';
import JiraDestinationForm from './index';

const emptyInitialValues = {
  outputId: null,
  displayName: '',
  defaultForSeverity: [],
  alertTypes: [],
  outputConfig: {
    jira: {
      orgDomain: '',
      apiKey: '',
      assigneeId: '',
      projectKey: '',
      issueType: '',
      userName: '',
      labels: [],
    },
  },
};

const displayName = 'Jira';
const severity = SeverityEnum.Critical;
const labels = ['panther', 'label'];

const initialValues = {
  outputId: '123',
  displayName,
  outputConfig: {
    jira: {
      orgDomain: faker.internet.url(),
      apiKey: '123231',
      assigneeId: '1',
      projectKey: 'key',
      issueType: 'Bug',
      userName: faker.internet.email(),
      labels: ['panther', 'label'],
    },
  },
  defaultForSeverity: [severity],
  alertTypes: [AlertTypesEnum.Rule, AlertTypesEnum.RuleError, AlertTypesEnum.Policy],
};

describe('JiraDestinationForm', () => {
  it('renders the correct fields', () => {
    const { getByLabelText, getAllByLabelText, getByText } = render(
      <JiraDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const orgDomainField = getByLabelText('* Organization Domain');
    const projectKeyField = getByLabelText('* Project Key');
    const emailField = getByLabelText('* Email');
    const apiKeyField = getByLabelText('* Jira API Key');
    const assigneeIdField = getByLabelText('Assignee ID');
    const issueTypeField = getByLabelText('* Issue Type');
    const labelsField = getAllByLabelText('Labels')[0];
    const submitButton = getByText('Add Destination');
    expect(displayNameField).toBeInTheDocument();
    expect(orgDomainField).toBeInTheDocument();
    expect(projectKeyField).toBeInTheDocument();
    expect(emailField).toBeInTheDocument();
    expect(apiKeyField).toBeInTheDocument();
    expect(assigneeIdField).toBeInTheDocument();
    expect(issueTypeField).toBeInTheDocument();
    expect(labelsField).toBeInTheDocument();
    expect(getAllByLabelText('Severity')[0]).toBeInTheDocument();
    expect(getAllByLabelText('Alert Types')[0]).toBeInTheDocument();

    expect(submitButton).toHaveAttribute('disabled');
  });

  it('has proper validation', async () => {
    const { getByLabelText, getAllByLabelText, getByText } = render(
      <JiraDestinationForm onSubmit={() => {}} initialValues={emptyInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const orgDomainField = getByLabelText('* Organization Domain');
    const projectKeyField = getByLabelText('* Project Key');
    const emailField = getByLabelText('* Email');
    const apiKeyField = getByLabelText('* Jira API Key');
    const assigneeIdField = getByLabelText('Assignee ID');
    const issueTypeField = getByLabelText('* Issue Type');
    const labelsField = getAllByLabelText('Labels')[0];
    const submitButton = getByText('Add Destination');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(orgDomainField, { target: { value: faker.internet.url() } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(projectKeyField, { target: { value: 'key' } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(emailField, { target: { value: faker.internet.email() } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(apiKeyField, { target: { value: 'api-key' } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(issueTypeField, { target: { value: 'Bug' } });
    await waitMs(1);
    // Labels is not required
    labels.forEach(label => {
      fireEvent.change(labelsField, {
        target: {
          value: label,
        },
      });
      fireEvent.blur(labelsField);
    });
    fireEvent.change(severityField, { target: { value: 'Critical' } });
    fireClickAndMouseEvents(getByText('Critical'));
    fireEvent.change(alertTypeField, { target: { value: 'Rule Matches' } });
    fireClickAndMouseEvents(getByText('Rule Matches'));
    await waitMs(1);
    // Assignee ID is not required
    expect(submitButton).not.toHaveAttribute('disabled');
    fireEvent.change(assigneeIdField, { target: { value: 'key' } });
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');
  });

  it('should trigger submit successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getAllByLabelText, getByText } = render(
      <JiraDestinationForm onSubmit={submitMockFunc} initialValues={emptyInitialValues} />
    );
    const jiraInput = buildJiraConfigInput({
      orgDomain: faker.internet.url(),
    });
    const displayNameField = getByLabelText('* Display Name');
    const orgDomainField = getByLabelText('* Organization Domain');
    const projectKeyField = getByLabelText('* Project Key');
    const emailField = getByLabelText('* Email');
    const apiKeyField = getByLabelText('* Jira API Key');
    const assigneeIdField = getByLabelText('Assignee ID');
    const issueTypeField = getByLabelText('* Issue Type');
    const labelsField = getAllByLabelText('Labels')[0];
    const submitButton = getByText('Add Destination');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypeField = getAllByLabelText('Alert Types')[0];
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    fireEvent.change(orgDomainField, { target: { value: jiraInput.orgDomain } });
    fireEvent.change(projectKeyField, { target: { value: jiraInput.projectKey } });
    fireEvent.change(emailField, { target: { value: jiraInput.userName } });
    fireEvent.change(apiKeyField, { target: { value: jiraInput.apiKey } });
    fireEvent.change(assigneeIdField, { target: { value: jiraInput.assigneeId } });
    fireEvent.change(issueTypeField, { target: { value: jiraInput.issueType } });
    jiraInput.labels.forEach(label => {
      fireEvent.change(labelsField, {
        target: {
          value: label,
        },
      });
      fireEvent.blur(labelsField);
    });
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
        outputConfig: { jira: jiraInput },
        defaultForSeverity: [severity],
        alertTypes: [AlertTypesEnum.Rule],
      },
      expect.toBeObject()
    );
  });

  it('should edit Jira Destination successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText } = render(
      <JiraDestinationForm onSubmit={submitMockFunc} initialValues={initialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const orgDomainField = getByLabelText('* Organization Domain');
    const projectKeyField = getByLabelText('* Project Key');
    const emailField = getByLabelText('* Email');
    const apiKeyField = getByLabelText('* Jira API Key');
    const assigneeIdField = getByLabelText('Assignee ID');
    const issueTypeField = getByLabelText('* Issue Type');
    const submitButton = getByText('Update Destination');
    expect(displayNameField).toHaveValue(initialValues.displayName);
    expect(orgDomainField).toHaveValue(initialValues.outputConfig.jira.orgDomain);
    expect(projectKeyField).toHaveValue(initialValues.outputConfig.jira.projectKey);
    expect(emailField).toHaveValue(initialValues.outputConfig.jira.userName);
    expect(apiKeyField).toHaveValue(initialValues.outputConfig.jira.apiKey);
    expect(assigneeIdField).toHaveValue(initialValues.outputConfig.jira.assigneeId);
    expect(issueTypeField).toHaveValue(initialValues.outputConfig.jira.issueType);
    expect(submitButton).toHaveAttribute('disabled');

    const newDisplayName = 'New Jira Name';
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
