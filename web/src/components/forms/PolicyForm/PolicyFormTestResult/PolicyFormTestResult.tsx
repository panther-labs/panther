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
import { ComplianceStatusEnum, TestPolicyRecord } from 'Generated/schema';
import { Card, Flex, Box, Heading, Text } from 'pouncejs';
import StatusBadge from 'Components/badges/StatusBadge';

interface PolicyFormTestResultProps {
  testResult: TestPolicyRecord;
}

const PolicyFormTestResult: React.FC<PolicyFormTestResultProps> = ({ testResult }) => {
  const {
    functions: { policyFunction },
    passed,
    name,
  } = testResult;

  return (
    <Card p={4} as="article">
      <Flex align="flex-start" spacing={4}>
        <StatusBadge status={passed ? ComplianceStatusEnum.Pass : ComplianceStatusEnum.Fail} />
        <Box spacing={2}>
          <Heading as="h2" size="x-small" fontWeight="medium">
            {name}
          </Heading>
          {policyFunction.error && (
            <React.Fragment>
              <Box as="dt" color="navyblue-100">
                Policy Body
              </Box>
              <Text as="dd" color="red-200">
                {policyFunction.error.message}
              </Text>
            </React.Fragment>
          )}
        </Box>
      </Flex>
    </Card>
  );
};

export default PolicyFormTestResult;
