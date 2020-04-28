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
import BlankCanvasImg from 'Assets/illustrations/blank-canvas.svg';
import urls from 'Source/urls';
import { Link as RRLink } from 'react-router-dom';

const ListResourcesPageEmptyDataFallback: React.FC = () => {
  return (
    <Flex justify="center" align="center" direction="column">
      <Box my={10}>
        <img alt="Black Canvas Illustration" src={BlankCanvasImg} width="auto" height={300} />
      </Box>
      <Heading size="medium" color="grey300" mb={6}>
        No resources found
      </Heading>
      <Text size="large" color="grey200" textAlign="center" mb={10}>
        You don{"'"}t have any resources connected to your Panther account
      </Text>
      <Button size="large" variant="primary" to={urls.compliance.sources.create()} as={RRLink}>
        Get started
      </Button>
    </Flex>
  );
};

export default ListResourcesPageEmptyDataFallback;
