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
import { ButtonProps, Button, Box, LinkProps } from 'pouncejs';
import { Link as RRLink, LinkProps as RRLinkProps } from 'react-router-dom';

type ButtonWithoutAs = Omit<ButtonProps, 'as'>;
type ToProp = Pick<RRLinkProps, 'to'>;
export type LinkButtonProps = ButtonWithoutAs & ToProp & { external?: boolean };
const LinkButton: React.FC<LinkButtonProps> = ({ disabled, external, to, children, ...rest }) => {
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
      <Button as="span" aria-disabled={disabled} {...rest}>
        {children}
      </Button>
    </Box>
  );
};
export default LinkButton;
