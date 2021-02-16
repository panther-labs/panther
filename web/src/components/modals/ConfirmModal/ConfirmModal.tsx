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
import { Box, Modal, Text, Flex, Button, ModalProps } from 'pouncejs';

export interface ConfirmModalProps extends ModalProps {
  title: string;
  subtitle: React.ReactNode;
  loading: boolean;
  onConfirm: () => void;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({
  subtitle,
  loading,
  onConfirm,
  onClose,
  ...rest
}) => {
  return (
    <Modal aria-describedby="modal-subtitle" onClose={onClose} {...rest}>
      <Box maxWidth={700}>
        <Text mb={8} textAlign="center" id="modal-subtitle">
          {subtitle}
        </Text>
        <Flex justify="flex-end" spacing={3}>
          <Button variant="outline" variantColor="navyblue" onClick={onClose}>
            Cancel
          </Button>
          <Button variantColor="red" onClick={onConfirm}>
            Confirm
          </Button>
        </Flex>
      </Box>
    </Modal>
  );
};

export default ConfirmModal;
