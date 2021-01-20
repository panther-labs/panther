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
  await waitMs(1);

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
  await waitMs(1);

  expect(queryByAriaLabel('Check is failing')).toBeFalsy();
  expect(getByAriaLabel('Check is passing')).toBeTruthy();
  expect(getByText(MIN_VALIDATION_MESSAGE)).toBeTruthy();
});
