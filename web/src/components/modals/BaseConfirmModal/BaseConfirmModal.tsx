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
import { Modal, Text, Flex, Button } from 'pouncejs';
import { MutationTuple } from '@apollo/client';
import SubmitButton from 'Components/buttons/SubmitButton';
import useModal from 'Hooks/useModal';

export interface BaseConfirmModalProps {
  mutation?: MutationTuple<any, { [key: string]: any }>;
  title: string;
  subtitle: React.ReactNode;
  onSuccessMsg?: string;
  onErrorMsg?: string;
  onSuccess?: () => void;
  onError?: () => void;
  onConfirm?: () => void;
  loading: boolean;
}

const BaseConfirmModal: React.FC<BaseConfirmModalProps> = ({
  title,
  subtitle,
  onConfirm = () => {},
  loading,
}) => {
  const {
    closeModal,
    hideModal,
    state: { hidden },
  } = useModal();

  function onClick() {
    hideModal();
    onConfirm();
  }
  if (hidden) return null;

  return (
    <Modal open onClose={closeModal} title={title}>
      <Text size="large" color="grey500" mb={8} textAlign="center">
        {subtitle}
      </Text>

      <Flex justifyContent="flex-end">
        <Button size="large" variant="default" onClick={closeModal} mr={3}>
          Cancel
        </Button>
        <SubmitButton onClick={() => onClick()} submitting={loading} disabled={loading}>
          Confirm
        </SubmitButton>
      </Flex>
    </Modal>
  );
};

export default BaseConfirmModal;
