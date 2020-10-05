import React from 'react';
import { ButtonProps, Button, Box } from 'pouncejs';
import { Link as RRLink, LinkProps as RRLinkProps } from 'react-router-dom';

type ButtonWithoutAs = Omit<ButtonProps, 'as'>;
type ToProp = Pick<RRLinkProps, 'to'>;

export type LinkButtonProps = ButtonWithoutAs & ToProp & { external?: boolean };

const LinkButton: React.FC<LinkButtonProps> = ({ external, to, children, ...rest }) => {
  const linkProps = external
    ? { target: '_blank', rel: 'noopener noreferrer', href: to, as: 'a' as React.ElementType }
    : { to, as: RRLink };

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
      <Button as="span" {...rest}>
        {children}
      </Button>
    </Box>
  );
};

export default LinkButton;
