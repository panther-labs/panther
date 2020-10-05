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
import WarningImg from 'Assets/illustrations/warning.svg';
import LinkButton from 'Components/buttons/LinkButton';
import withSEO from 'Hoc/withSEO';

const Page500: React.FC = () => {
  return (
    <Flex justify="center" align="center" direction="column">
      <Box mb={10}>
        <img alt="Page crash illustration" src={WarningImg} width="auto" height={350} />
      </Box>
      <Heading mb={2}>Something went terribly wrong</Heading>
      <Text fontSize="medium" color="gray-300" mb={10}>
        This would normally be an internal server error, but we are fully serverless. Feel free to
        laugh.
      </Text>
      <LinkButton to="/">Back to somewhere stable</LinkButton>
    </Flex>
  );
};

export default withSEO({ title: 'Internal Server Error' })(Page500);
