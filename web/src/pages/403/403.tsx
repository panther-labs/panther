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
import useAuth from 'Hooks/useAuth';
import AccessDeniedImg from 'Assets/illustrations/authentication.svg';
import withSEO from 'Hoc/withSEO';
import LinkButton from 'Components/buttons/LinkButton';

const Page403: React.FC = () => {
  const { userInfo } = useAuth();

  return (
    <Flex justify="center" align="center" direction="column">
      <Box mb={10}>
        <img alt="Access denied illustration" src={AccessDeniedImg} width="auto" height={400} />
      </Box>
      <Heading mb={2}>
        You have no power here, {userInfo ? userInfo.givenName : 'Anonymous'} the Grey
      </Heading>
      <Text fontSize="medium" color="gray-300" mb={10}>
        ( Sarum... Your administrator has restricted your powers )
      </Text>
      <LinkButton to="/">Back to Shire</LinkButton>
    </Flex>
  );
};

export default withSEO({ title: 'Permission Denied' })(Page403);
