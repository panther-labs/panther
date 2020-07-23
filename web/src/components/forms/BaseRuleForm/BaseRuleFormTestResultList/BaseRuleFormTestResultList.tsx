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
import { Box, Flex, Text } from 'pouncejs';
import { ComplianceStatusEnum, TestPolicyResponse } from 'Generated/schema';
import PolicyFormTestResult, { mapTestStatusToColor } from '../BaseRuleFormTestResult';

interface PolicyFormTestResultsProps {
  results: TestPolicyResponse;
  running: boolean;
}

const BaseRuleFormTestResultList: React.FC<PolicyFormTestResultsProps> = ({ running, results }) => {
  return (
    <Box bg="navyblue-300" fontSize="medium" fontWeight="medium" p={5}>
      {running && 'Running your tests...'}
      {!running && results && (
        <Flex direction="column" spacing={2}>
          {results.testsPassed.map(testName => (
            <PolicyFormTestResult
              key={testName}
              testName={testName}
              status={ComplianceStatusEnum.Pass}
              text="Test Passed"
            />
          ))}
          {results.testsFailed.map(testName => (
            <PolicyFormTestResult
              key={testName}
              testName={testName}
              status={ComplianceStatusEnum.Fail}
              text="Test Failed"
            />
          ))}
          {results.testsErrored.map(({ name: testName, errorMessage }) => (
            <Box key={testName}>
              <PolicyFormTestResult
                testName={testName}
                status={ComplianceStatusEnum.Error}
                text="Error"
              />
              <Text
                ml={1}
                mt={1}
                fontSize="x-small"
                fontWeight="bold"
                color={mapTestStatusToColor[ComplianceStatusEnum.Error]}
              >
                {errorMessage}
              </Text>
            </Box>
          ))}
        </Flex>
      )}
    </Box>
  );
};

export default React.memo(BaseRuleFormTestResultList);
