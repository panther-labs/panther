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
import { Modal, Text, Flex, Button } from 'pouncejs';
import SubmitButton from 'Components/buttons/SubmitButton';

export interface ConfirmModalProps {
  title: string;
  subtitle: React.ReactNode;
  loading: boolean;
  onConfirm: () => void;
  onClose: () => void;
}

const ConfirmModal: React.FC<ConfirmModalProps> = ({
  title,
  subtitle,
  loading,
  onConfirm,
  onClose,
}) => {
  return (
    <Modal open onClose={onClose} title={title}>
      <Text size="large" color="grey500" mb={8} textAlign="center">
        {subtitle}
      </Text>
      <Flex justify="flex-end">
        <Button size="large" variant="default" onClick={onClose} mr={3}>
          Cancel
        </Button>
        <SubmitButton onClick={onConfirm} submitting={loading} disabled={loading}>
          Confirm
        </SubmitButton>
      </Flex>
    </Modal>
  );
};

export default ConfirmModal;
