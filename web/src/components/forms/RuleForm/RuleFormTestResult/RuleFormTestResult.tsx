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
import { ComplianceStatusEnum, TestRuleRecord } from 'Generated/schema';
import { Card, Flex, Box, Heading, Text, Grid } from 'pouncejs';
import StatusBadge from 'Components/badges/StatusBadge';

interface RuleFormTestResultProps {
  testResult: TestRuleRecord;
}

const RuleFormTestResult: React.FC<RuleFormTestResultProps> = ({ testResult }) => {
  const {
    functions: { ruleFunction, dedupFunction, titleFunction },
    passed,
    name,
    error: unknownError,
  } = testResult;

  return (
    <Card p={4} as="article">
      <Flex align="flex-start" spacing={4}>
        <StatusBadge status={passed ? ComplianceStatusEnum.Pass : ComplianceStatusEnum.Fail} />
        <Box spacing={2}>
          <Heading as="h2" size="x-small" fontWeight="medium">
            {name}
          </Heading>
          <Grid
            as="dl"
            wordBreak="break-word"
            templateColumns="max-content 1fr"
            fontSize="medium"
            fontWeight="medium"
            columnGap={4}
            rowGap={2}
            mt={2}
          >
            {unknownError && (
              <React.Fragment>
                <Box as="dt" color="navyblue-100">
                  Error
                </Box>
                <Text as="dd" color="red-200">
                  {unknownError.message}
                </Text>
              </React.Fragment>
            )}
            {ruleFunction?.error && (
              <React.Fragment>
                <Box as="dt" color="navyblue-100">
                  Rule Body
                </Box>
                <Text as="dd" color="red-200">
                  {ruleFunction.error.message}
                </Text>
              </React.Fragment>
            )}
            {titleFunction && (
              <React.Fragment>
                <Box as="dt" color="navyblue-100">
                  Alert Title
                </Box>
                {!titleFunction.error ? (
                  <Text as="dd">{titleFunction.output}</Text>
                ) : (
                  <Text as="dd" color="red-200">
                    {titleFunction.error.message}
                  </Text>
                )}
              </React.Fragment>
            )}
            {dedupFunction && (
              <React.Fragment>
                <Box as="dt" color="navyblue-100">
                  Dedup String
                </Box>
                {!dedupFunction.error ? (
                  <Text as="dd">{dedupFunction.output}</Text>
                ) : (
                  <Text as="dd" color="red-200">
                    {dedupFunction.error.message}
                  </Text>
                )}
              </React.Fragment>
            )}
          </Grid>
        </Box>
      </Flex>
    </Card>
  );
};

export default RuleFormTestResult;
