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
import { Flex, Heading, Text, Box } from 'pouncejs';
import NotFoundImg from 'Assets/illustrations/not-found.svg';
import withSEO from 'Hoc/withSEO';
import LinkButton from 'Components/buttons/LinkButton';

const Page404: React.FC = () => {
  return (
    <Flex justify="center" align="center" direction="column" height="100%" width="100%">
      <Box mb={10}>
        <img alt="Page not found illustration" src={NotFoundImg} width="auto" height={400} />
      </Box>
      <Heading mb={2}>Not all who wander are lost...</Heading>
      <Text color="gray-300" mb={10}>
        ( You definitely are though )
      </Text>
      <LinkButton to="/">Back to Home</LinkButton>
    </Flex>
  );
};

export default withSEO({ title: 'Not Found' })(Page404);
