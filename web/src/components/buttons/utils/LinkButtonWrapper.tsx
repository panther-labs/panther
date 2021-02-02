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
import { Box, LinkProps } from 'pouncejs';
import { Link as RRLink } from 'react-router-dom';

export type LinkButtonWrapperProps = Pick<LinkProps, 'external' | 'disabled' | 'to'>;

const LinkButton: React.FC<LinkButtonWrapperProps> = ({ disabled, external, to, children }) => {
  let linkProps: LinkProps;
  if (disabled) {
    linkProps = { as: 'span' as React.ElementType };
  } else if (!external) {
    linkProps = { to, as: RRLink };
  } else {
    linkProps = {
      target: '_blank',
      rel: 'noopener noreferrer',
      href: to as string,
      as: 'a' as React.ElementType,
    };
  }
  return (
    <Box
      {...linkProps}
      sx={{
        '& > span': {
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
        },
      }}
    >
      {children}
    </Box>
  );
};
export default LinkButton;
