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
import { render, fireEvent, waitFor, waitMs, fireClickAndMouseEvents } from 'test-utils';
import { AlertTypesEnum, SeverityEnum } from 'Generated/schema';
import { Field } from 'formik';
import FormikTextInput from 'Components/fields/TextInput';
import BaseDestinationForm, { BaseDestinationFormValues, defaultValidationSchema } from './index';

const emptyInitialValues = {
  displayName: '',
  defaultForSeverity: [],
  alertTypes: [],
  outputConfig: {},
};

const displayName = 'Base form';
const criticalSeverity = SeverityEnum.Critical;
const criticalText = 'Critical';
const ruleMatchText = 'Rule Matches';

const defaultInitialValues = {
  outputId: 'id',
  displayName,
  outputConfig: {},
  defaultForSeverity: [criticalSeverity],
  alertTypes: Object.values(AlertTypesEnum),
};

const BasicForm: React.FC<{
  initialValues: BaseDestinationFormValues<any>;
  onSubmit: () => void;
}> = ({ initialValues, onSubmit }) => {
  return (
    <BaseDestinationForm
      onSubmit={onSubmit}
      initialValues={initialValues}
      validationSchema={defaultValidationSchema}
    >
      <Field
        name="displayName"
        as={FormikTextInput}
        label="* Display Name"
        placeholder="How should we name this?"
        required
      />
    </BaseDestinationForm>
  );
};

describe('BaseDestinationForm', () => {
  it('renders the correct fields', () => {
    const { getAllByLabelText, getByLabelText, getByText } = render(
      <BasicForm initialValues={emptyInitialValues} onSubmit={() => {}} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypesField = getAllByLabelText('Alert Types')[0];
    const submitButton = getByText('Add Destination');
    expect(displayNameField).toBeInTheDocument();
    expect(severityField).toBeInTheDocument();
    expect(alertTypesField).toBeInTheDocument();
    expect(submitButton).toBeInTheDocument();

    expect(submitButton).toHaveAttribute('disabled');
  });

  it('has proper validation', async () => {
    const { getAllByLabelText, getByLabelText, getByText } = render(
      <BasicForm initialValues={emptyInitialValues} onSubmit={() => {}} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypesField = getAllByLabelText('Alert Types')[0];
    const submitButton = getByText('Add Destination');
    expect(displayNameField).toBeInTheDocument();
    expect(severityField).toBeInTheDocument();
    expect(alertTypesField).toBeInTheDocument();
    expect(submitButton).toBeInTheDocument();

    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(displayNameField, { target: { value: displayName } });
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(severityField, { target: { value: criticalText } });
    fireClickAndMouseEvents(getByText(criticalText));
    await waitMs(1);
    expect(submitButton).toHaveAttribute('disabled');
    fireEvent.change(alertTypesField, { target: { value: ruleMatchText } });
    fireClickAndMouseEvents(getByText(ruleMatchText));
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');
  });

  it('should trigger submit successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getAllByLabelText, getByLabelText, getByText } = render(
      <BasicForm initialValues={emptyInitialValues} onSubmit={submitMockFunc} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const severityField = getAllByLabelText('Severity')[0];
    const alertTypesField = getAllByLabelText('Alert Types')[0];
    const submitButton = getByText('Add Destination');
    expect(submitButton).toHaveAttribute('disabled');

    fireEvent.change(displayNameField, { target: { value: displayName } });
    fireEvent.change(severityField, { target: { value: criticalText } });
    fireClickAndMouseEvents(getByText(criticalText));
    fireEvent.change(alertTypesField, { target: { value: ruleMatchText } });
    fireClickAndMouseEvents(getByText(ruleMatchText));

    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');

    fireEvent.click(submitButton);
    await waitFor(() => expect(submitMockFunc).toHaveBeenCalledTimes(1));
    expect(submitMockFunc).toHaveBeenCalledWith(
      {
        displayName,
        outputConfig: {},
        defaultForSeverity: [SeverityEnum.Critical],
        alertTypes: [AlertTypesEnum.Rule],
      },
      expect.toBeObject()
    );
  });

  it('should edit successfully', async () => {
    const submitMockFunc = jest.fn();
    const { getByLabelText, getByText } = render(
      <BasicForm onSubmit={submitMockFunc} initialValues={defaultInitialValues} />
    );
    const displayNameField = getByLabelText('* Display Name');
    const submitButton = getByText('Update Destination');
    expect(displayNameField).toHaveValue(defaultInitialValues.displayName);
    expect(submitButton).toHaveAttribute('disabled');

    const newDisplayName = 'New Display Name';
    fireEvent.change(displayNameField, { target: { value: newDisplayName } });
    await waitMs(1);
    expect(submitButton).not.toHaveAttribute('disabled');

    fireEvent.click(submitButton);
    await waitFor(() => expect(submitMockFunc).toHaveBeenCalledTimes(1));
    expect(submitMockFunc).toHaveBeenCalledWith(
      {
        outputId: defaultInitialValues.outputId,
        displayName: newDisplayName,
        outputConfig: defaultInitialValues.outputConfig,
        defaultForSeverity: defaultInitialValues.defaultForSeverity,
        alertTypes: defaultInitialValues.alertTypes,
      },
      expect.toBeObject()
    );
  });
});
