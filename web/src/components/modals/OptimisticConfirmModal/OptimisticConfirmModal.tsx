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
import { Button, Flex, Modal, ModalProps, Text } from 'pouncejs';
import LoadingButton from 'Components/buttons/LoadingButton';

export interface OptimisticConfirmModalProps extends ModalProps {
  subtitle: React.ReactNode;
  onConfirm: () => void;
}

const OptimisticConfirmModal: React.FC<OptimisticConfirmModalProps> = ({
  subtitle,
  onConfirm,
  onClose,
  ...rest
}) => {
  const handleConfirm = () => {
    onConfirm();
    onClose();
  };

  return (
    <Modal onClose={onClose} {...rest}>
      <Text size="large" color="grey500" mb={8} textAlign="center">
        {subtitle}
      </Text>

      <Flex justify="flex-end">
        <Button size="large" variant="outline" onClick={onClose} mr={3}>
          Cancel
        </Button>
        <LoadingButton onClick={handleConfirm}>Confirm</LoadingButton>
      </Flex>
    </Modal>
  );
};

export default OptimisticConfirmModal;
