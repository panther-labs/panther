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
import { Box, Button, Flex, Heading, Text } from 'pouncejs';
import useAuth from 'Hooks/useAuth';
import { Link as RRLink } from 'react-router-dom';
import AccessDeniedImg from 'Assets/illustrations/authentication.svg';

const Page403: React.FC = () => {
  const { userInfo } = useAuth();

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
        <img alt="Access denied illustration" src={AccessDeniedImg} width="auto" height={400} />
      </Box>
      <Heading size="medium" color="grey300" mb={4}>
        You have no power here, {userInfo ? userInfo.given_name : 'Anonymous'} the Grey
      </Heading>
      <Text size="medium" color="grey200" as="p" mb={10}>
        ( Sarum... Your administrator has restricted your powers )
      </Text>
      <Button size="small" variant="default" as={RRLink} to="/">
        Back to Shire
      </Button>
    </Flex>
  );
};

export default Page403;
