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
import LinkButton, { LinkButtonProps } from '../LinkButton';

export type CancelButtonProps = Omit<LinkButtonProps, 'variantColor' | 'icon'>;

const CancelButton: React.FC<CancelButtonProps> = ({ ...rest }) => {
  return <LinkButton variantColor="darkgray" icon="close-outline" {...rest} />;
};

export default React.memo(CancelButton);
