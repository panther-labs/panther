/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { Box, Label } from 'pouncejs';
import { ComplianceStatusEnum, TestPolicyResponse } from 'Generated/schema';
import PolicyFormTestResult, { mapTestStatusToColor } from '../BaseRuleFormTestResult';

interface PolicyFormTestResultsProps {
  results: TestPolicyResponse;
  running: boolean;
}

const BaseRuleFormTestResultList: React.FC<PolicyFormTestResultsProps> = ({ running, results }) => {
  return (
    // @ts-ignore
    <Box bg="#FEF5ED" p={5}>
      {running && (
        <Label size="medium" is="p">
          Running your tests...
        </Label>
      )}
      {!running && results && (
        <React.Fragment>
          {results.testsPassed.map(testName => (
            <Box mb={1} key={testName}>
              <PolicyFormTestResult testName={testName} status={ComplianceStatusEnum.Pass} />
            </Box>
          ))}
          {results.testsFailed.map(testName => (
            <Box mb={1} key={testName}>
              <PolicyFormTestResult testName={testName} status={ComplianceStatusEnum.Fail} />
            </Box>
          ))}
          {results.testsErrored.map(({ name: testName, errorMessage }) => (
            <Box key={testName} mb={1}>
              <PolicyFormTestResult testName={testName} status={ComplianceStatusEnum.Error} />
              <Label size="small" is="pre" color={mapTestStatusToColor[ComplianceStatusEnum.Error]}>
                {errorMessage}
              </Label>
            </Box>
          ))}
        </React.Fragment>
      )}
    </Box>
  );
};

export default React.memo(BaseRuleFormTestResultList);
