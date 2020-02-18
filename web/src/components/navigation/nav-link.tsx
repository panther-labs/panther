import { Flex, Icon, IconButtonProps, IconProps, MenuItem } from 'pouncejs';
import React from 'react';
import useRouter from 'Hooks/useRouter';
import { Link } from 'react-router-dom';
import { css } from '@emotion/core';

type NavLinkProps = Omit<IconButtonProps, 'variant'> & {
  icon: IconProps['type'];
  label: string;
  to: string;
};

const NavLink: React.FC<NavLinkProps> = ({ icon, label, to }) => {
  const { location } = useRouter();

  return (
    <MenuItem
      width={1}
      variant="primary"
      selected={location.pathname === to}
      my={2}
      is={Link}
      to={to}
      css={css`
        text-decoration: none;
      `}
      aria-label={label}
    >
      <Flex alignItems="center" px={4}>
        <Icon type={icon} size="small" mr={6} />
        {label}
      </Flex>
    </MenuItem>
  );
};

export default NavLink;
