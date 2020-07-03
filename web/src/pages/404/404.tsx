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
import { Flex, Heading, Text, Button, Box } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';
import NotFoundImg from 'Assets/illustrations/not-found.svg';
import withSEO from 'Hoc/withSEO';

const Page404: React.FC = () => {
  return (
    <Flex
      justify="center"
      align="center"
      width="100vw"
      height="100vh"
      position="fixed"
      left={0}
      top={0}
      direction="column"
    >
      <Box mb={10}>
        <img alt="Page not found illustration" src={NotFoundImg} width="auto" height={400} />
      </Box>
      <Heading mb={2}>Not all who wander are lost...</Heading>
      <Text color="gray-200" mb={10}>
        ( You definitely are though )
      </Text>
      <Button as={RRLink} to="/">
        Back to Home
      </Button>
    </Flex>
  );
};

export default withSEO({ title: 'Not Found' })(Page404);
