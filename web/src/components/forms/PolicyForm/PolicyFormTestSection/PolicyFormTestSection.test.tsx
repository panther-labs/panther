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
  buildDetectionTestDefinition,
  buildDetectionTestDefinitionInput,
  buildError,
  buildPolicy,
  buildTestPolicyRecord,
  render,
  fireEvent,
  buildTestPolicyRecordFunctions,
  buildTestDetectionSubRecord,
} from 'test-utils';
import { UpdatePolicyInput } from 'Generated/schema';
import { Formik } from 'formik';
import { PolicyFormValues } from '../PolicyForm';
import PolicyFormTestSection from './PolicyFormTestSection';
import { mockTestPolicy } from './graphql/testPolicy.generated';

describe('PolicyFormTestSection', () => {
  it('correctly renders the test results', async () => {
    const policy = buildPolicy({
      tests: [
        buildDetectionTestDefinition({
          expectedResult: true,
          name: 'Test 1',
          resource: '{}',
        }),
        buildDetectionTestDefinition({
          expectedResult: false,
          name: 'Test 2',
          resource: '{}',
        }),
      ],
    });

    const mocks = [
      mockTestPolicy({
        variables: {
          input: {
            body: policy.body,
            resourceTypes: policy.resourceTypes,
            tests: [
              buildDetectionTestDefinitionInput({
                expectedResult: true,
                name: 'Test 1',
                resource: '{}',
              }),
              buildDetectionTestDefinitionInput({
                expectedResult: false,
                name: 'Test 2',
                resource: '{}',
              }),
            ],
          },
        },
        data: {
          testPolicy: {
            results: [
              buildTestPolicyRecord({
                id: 'Test 1',
                name: 'Test 1',
                passed: true,
                functions: buildTestPolicyRecordFunctions({
                  policyFunction: buildTestDetectionSubRecord({ error: null }),
                }),
              }),
              buildTestPolicyRecord({
                id: 'Test 2',
                name: 'Test 2',
                passed: false,
                functions: buildTestPolicyRecordFunctions({
                  policyFunction: buildTestDetectionSubRecord({
                    error: buildError({ message: 'Not Good' }),
                  }),
                }),
              }),
            ],
          },
        },
      }),
    ];

    const { getByText, findByText } = render(
      <Formik<PolicyFormValues>
        initialValues={policy as Required<UpdatePolicyInput>}
        onSubmit={jest.fn()}
      >
        <PolicyFormTestSection />
      </Formik>,
      { mocks }
    );

    // Run the tests
    fireEvent.click(getByText('Run All'));

    // Initially we should see a loading placeholder
    expect(getByText('Running your tests...')).toBeInTheDocument();

    // One should pass without any other message
    expect(await findByText('PASS')).toBeInTheDocument();

    // The other should fail
    expect(getByText('FAIL')).toBeInTheDocument();
    expect(getByText('Not Good')).toBeInTheDocument();
  });
});
