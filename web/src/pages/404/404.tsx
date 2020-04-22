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
      bg="white"
      direction="column"
    >
      <Box mb={10}>
        <img alt="Page not found illustration" src={NotFoundImg} width="auto" height={400} />
      </Box>
      <Heading size="medium" color="grey300" mb={4}>
        Not all who wander are lost...
      </Heading>
      <Text size="large" color="grey200" as="p" mb={10}>
        ( You definitely are though )
      </Text>
      <Button size="small" variant="default" as={RRLink} to="/">
        Back to Home
      </Button>
    </Flex>
  );
};

export default Page404;
