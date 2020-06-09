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
import { Box, Flex, Modal, ModalProps, Text } from 'pouncejs';
import LoadingButton from 'Components/buttons/LoadingButton';

const NetworkErrorModal: React.FC<ModalProps> = props => {
  return (
    <Modal title="No Internet Connection" {...props}>
      <Box width={600}>
        <Text size="large" color="grey300" my={10} textAlign="center">
          Somebody is watching cat videos and is preventing you from being online
          <br />
          <br />
          That{"'"}s the most likely scenario anyway...
        </Text>
        <Flex justify="center" mb={5}>
          <LoadingButton loading disabled>
            Reconnecting
          </LoadingButton>
        </Flex>
      </Box>
    </Modal>
  );
};

export default NetworkErrorModal;
