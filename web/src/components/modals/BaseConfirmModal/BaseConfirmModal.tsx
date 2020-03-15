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
import { Modal, Text, Flex, Button, useSnackbar } from 'pouncejs';
import { MutationTuple } from '@apollo/client';
import { SubmitButton } from 'Components/Buttons';
import useModal from 'Hooks/useModal';

export interface BaseConfirmModalProps {
  mutation: MutationTuple<any, { [key: string]: any }>;
  title: string;
  subtitle: string;
  onSuccessMsg: string;
  onErrorMsg: string;
  onSuccess?: () => void;
  onError?: () => void;
}

const BaseConfirmModal: React.FC<BaseConfirmModalProps> = ({
  mutation,
  title,
  subtitle,
  onErrorMsg,
  onSuccessMsg,
  onSuccess = () => {},
  onError = () => {},
}) => {
  const { pushSnackbar } = useSnackbar();
  const { hideModal } = useModal();
  const [confirm, { loading, data, error }] = mutation;

  React.useEffect(() => {
    if (error) {
      pushSnackbar({ variant: 'error', title: onErrorMsg });
      onError();
    }
  }, [error]);

  React.useEffect(() => {
    if (data) {
      pushSnackbar({ variant: 'success', title: onSuccessMsg });
      hideModal();
      onSuccess();
    }
  }, [data]);

  return (
    <Modal open onClose={hideModal} title={title}>
      <Text size="large" color="grey500" mb={8} textAlign="center">
        {subtitle}
      </Text>

      <Flex justifyContent="flex-end">
        <Button size="large" variant="default" onClick={hideModal} mr={3}>
          Cancel
        </Button>
        <SubmitButton onClick={() => confirm()} submitting={loading} disabled={loading}>
          Confirm
        </SubmitButton>
      </Flex>
    </Modal>
  );
};

export default BaseConfirmModal;
