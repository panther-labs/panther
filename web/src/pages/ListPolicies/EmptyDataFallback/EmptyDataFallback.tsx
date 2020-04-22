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
import { Box, Flex, Heading, Text } from 'pouncejs';
import EmptyNotepadImg from 'Assets/illustrations/empty-notepad.svg';
import PolicyCreateButton from '../CreateButton';

const ListPoliciesPageEmptyDataFallback: React.FC = () => {
  return (
    <Flex justify="center" align="center" direction="column">
      <Box my={10}>
        <img alt="Empty Notepad Illustration" src={EmptyNotepadImg} width="auto" height={300} />
      </Box>
      <Heading size="medium" color="grey300" mb={6}>
        No policies found
      </Heading>
      <Text size="large" color="grey200" textAlign="center" mb={10}>
        Writing policies is the only way to secure your infrastructure against misconfigurations
      </Text>
      <PolicyCreateButton />
    </Flex>
  );
};

export default ListPoliciesPageEmptyDataFallback;
