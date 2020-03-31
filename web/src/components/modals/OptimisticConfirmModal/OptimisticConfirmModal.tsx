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
import ConfirmModal from 'Components/modals/ConfirmModal';
import useModal from 'Hooks/useModal';

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
    <ConfirmModal
      title={title}
      subtitle={subtitle}
      loading={false}
      onConfirm={handleConfirm}
      onClose={hideModal}
    />
  );
};

export default OptimisticConfirmModal;
