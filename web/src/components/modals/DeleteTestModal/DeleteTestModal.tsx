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
import { ModalProps } from 'pouncejs';
import { DetectionTestDefinition, DetectionTestDefinitionInput } from 'Generated/schema';
import OptimisticConfirmModal from '../OptimisticConfirmModal';

export interface DeleteTestModalProps extends ModalProps {
  test: DetectionTestDefinition | DetectionTestDefinitionInput;
  onConfirm: () => void;
}

const DeleteTestModal: React.FC<DeleteTestModalProps> = ({ test, onConfirm, ...rest }) => {
  return (
    <OptimisticConfirmModal
      title="Delete Test"
      subtitle={`Are you sure you want to delete ${test.name}?`}
      onConfirm={onConfirm}
      {...rest}
    />
  );
};

export default DeleteTestModal;
