/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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
import { Flex, Heading, Text } from 'pouncejs';
import SubmitButton from 'Components/submit-button';

interface SuccessPanelProps {
  loading: boolean;
}

const SuccessPanel: React.FC<SuccessPanelProps> = ({ loading }) => {
  return (
    <Flex
      justifyContent="center"
      alignItems="center"
      flexDirection="column"
      my={190}
      mx="auto"
      width={350}
    >
      <Heading size="medium" m="auto" mb={5} color="grey400">
        Almost done!
      </Heading>
      <Text size="large" color="grey300" mb={10}>
        Click the button below to complete the setup!
      </Text>
      <SubmitButton width={350} disabled={loading} submitting={loading}>
        Add New Source
      </SubmitButton>
    </Flex>
  );
};

export default SuccessPanel;
