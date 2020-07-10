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
import { ComplianceStatusEnum } from 'Generated/schema';
import { Card, theme, Flex, Box } from 'pouncejs';

// A mapping from status to background color for our test results (background color of where it says
// 'pass', 'fail' or 'error'
export const mapTestStatusToColor: {
  [key in ComplianceStatusEnum]: keyof typeof theme['colors'];
} = {
  [ComplianceStatusEnum.Pass]: 'green-200',
  [ComplianceStatusEnum.Fail]: 'red-200',
  [ComplianceStatusEnum.Error]: 'orange-500',
};

interface BaseRuleFormTestResultProps {
  /** The name of the test */
  testName: string;

  /** The result of the text */
  status: ComplianceStatusEnum;

  /** The value that is going to displayed to the user as a result for this test */
  text: string;
}

const BaseRuleFormTestResult: React.FC<BaseRuleFormTestResultProps> = ({
  testName,
  status,
  text,
}) => (
  <Flex align="center">
    <Card bg={mapTestStatusToColor[status]} mr={2} width={90} py={1}>
      <Box
        fontSize="small"
        fontWeight="bold"
        mx="auto"
        textAlign="center"
        textTransform="uppercase"
      >
        {text}
      </Box>
    </Card>
    <Box fontSize="medium" fontWeight="medium">
      {testName}
    </Box>
  </Flex>
);

export default BaseRuleFormTestResult;
