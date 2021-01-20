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
import { Alert, Flex, Card } from 'pouncejs';
import { DetectionTestDefinition } from 'Generated/schema';
import { useFormikContext } from 'formik';
import { PolicyFormValues } from 'Components/forms/PolicyForm';
import { BaseDetectionFormTestSection } from 'Components/forms/BaseDetectionForm';
import { extractErrorMessage } from 'Helpers/utils';
import { useTestPolicy } from './graphql/testPolicy.generated';
import RuleFormTestResult from '../PolicyFormTestResult';

const PolicyFormTestSection: React.FC = () => {
  // Read the values from the "parent" form. We expect a formik to be declared in the upper scope
  // since this is a "partial" form. If no Formik context is found this will error out intentionally
  const {
    values: { resourceTypes, body },
  } = useFormikContext<PolicyFormValues>();

  // Load the mutation that will perform the policy testing but we are not yet populating it with
  // the variables since we'll do that on "click" - time
  // prettier-ignore
  const [testPolicy, { error, loading, data }] = useTestPolicy();

  // Helper function where the only thing parameterised is the array of tests to submit to the server
  // This helps us reduce the amount of code we write when the only thing changing is the number of
  // tests to run
  const runTests = React.useCallback(
    (testsToRun: DetectionTestDefinition[]) => {
      testPolicy({
        variables: {
          input: {
            body,
            resourceTypes,
            tests: testsToRun,
          },
        },
      });
    },
    [body, resourceTypes]
  );
  return (
    <BaseDetectionFormTestSection
      type="policy"
      runTests={runTests}
      renderTestResults={
        <React.Fragment>
          {error && (
            <Alert
              variant="error"
              title="Internal error during testing"
              description={
                extractErrorMessage(error) ||
                "An unknown error occured and we couldn't run your tests"
              }
            />
          )}
          {loading && (
            <Card fontSize="medium" fontWeight="medium" p={4}>
              Running your tests...
            </Card>
          )}
          {data && (
            <Flex direction="column" spacing={4}>
              {data.testPolicy.results.map(testResult => (
                <RuleFormTestResult key={testResult.id} testResult={testResult} />
              ))}
            </Flex>
          )}
        </React.Fragment>
      }
    />
  );
};

export default PolicyFormTestSection;
