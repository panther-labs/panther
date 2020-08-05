import React from 'react';
import { render, waitMs } from 'test-utils';
import * as Yup from 'yup';
import FieldPolicyChecker from './index';

const REQUIRED_VALIDATION_MESSAGE = 'Required';
const MIN_VALIDATION_MESSAGE = 'Must be at least 5 chars';
const schema = Yup.string().required(REQUIRED_VALIDATION_MESSAGE).min(5, MIN_VALIDATION_MESSAGE);

test('it renders the failing checks based on the schema', async () => {
  const { queryByText, getByAriaLabel, getByText } = render(
    <FieldPolicyChecker schema={schema} value="" />
  );

  // wait for yup to run validations
  await waitMs(10);

  // required should never be displayed as per spec
  expect(queryByText(REQUIRED_VALIDATION_MESSAGE)).toBeFalsy();
  expect(getByAriaLabel('Check is failing')).toBeTruthy();
  expect(getByText(MIN_VALIDATION_MESSAGE)).toBeTruthy();
});

test('it renders the passing checks based on the schema', async () => {
  const { queryByAriaLabel, getByAriaLabel, getByText } = render(
    <FieldPolicyChecker schema={schema} value="abcde" />
  );

  // wait for yup to run validations
  await waitMs(10);

  expect(queryByAriaLabel('Check is failing')).toBeFalsy();
  expect(getByAriaLabel('Check is passing')).toBeTruthy();
  expect(getByText(MIN_VALIDATION_MESSAGE)).toBeTruthy();
});
