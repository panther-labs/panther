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
import { Button, Spinner, Flex, ButtonProps } from 'pouncejs';

const SubmitButton: React.FC<Omit<ButtonProps, 'size' | 'variant'> & { submitting: boolean }> = ({
  submitting,
  disabled,
  children,
  ...rest
}) => (
  <Button {...rest} type="submit" size="large" variant="primary" disabled={disabled}>
    {submitting ? (
      <Flex alignItems="center" justifyContent="center">
        <Spinner size="small" mr={2} />
        {children}
      </Flex>
    ) : (
      children
    )}
  </Button>
);

export default React.memo(SubmitButton);
