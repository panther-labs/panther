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
import useModal from 'Hooks/useModal';
import { Button, Flex, Modal, Text } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton/SubmitButton';

export interface OptimisticConfirmModalProps {
  title: string;
  subtitle: React.ReactNode;
  onConfirm: () => void;
}

const OptimisticConfirmModal: React.FC<OptimisticConfirmModalProps> = ({
  title,
  subtitle,
  onConfirm,
}) => {
  const { hideModal } = useModal();

  const handleConfirm = () => {
    onConfirm();
    hideModal();
  };

  return (
    <Modal open onClose={hideModal} title={title}>
      <Text size="large" color="grey500" mb={8} textAlign="center">
        {subtitle}
      </Text>

      <Flex justify="flex-end">
        <Button size="large" variant="default" onClick={hideModal} mr={3}>
          Cancel
        </Button>
        <SubmitButton onClick={handleConfirm} submitting={false} disabled={false}>
          Confirm
        </SubmitButton>
      </Flex>
    </Modal>
  );
};

export default OptimisticConfirmModal;
