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
import { AbstractButton } from 'pouncejs';

interface ScaleButtonProps {
  title: string;
  selected: boolean;
  onClick: () => void;
}

const ScaleButton: React.FC<ScaleButtonProps> = ({ title, selected, onClick }) => {
  return (
    <AbstractButton
      borderRadius="pill"
      py={1}
      px={4}
      fontSize="small"
      backgroundColor={selected ? 'blue-400' : 'transparent'}
      _hover={!selected && { backgroundColor: 'navyblue-300' }}
      onClick={onClick}
    >
      {title}
    </AbstractButton>
  );
};

export default ScaleButton;
