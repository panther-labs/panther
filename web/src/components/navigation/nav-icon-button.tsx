import { Flex, Icon, IconButton, IconButtonProps, IconProps, Label, Tooltip } from 'pouncejs';
import React from 'react';

type NavIconButtonProps = Omit<IconButtonProps, 'variant'> & {
  icon: IconProps['type'];
  tooltipLabel: string;
};

const NavIconButton: React.FC<NavIconButtonProps> = ({ icon, active, tooltipLabel, ...rest }) => (
  <Tooltip content={<Label size="medium">{tooltipLabel}</Label>}>
    <Flex>
      <IconButton {...rest} variant="primary" my={4} active={active} aria-label={tooltipLabel}>
        <Icon type={icon} size="small" />
      </IconButton>
    </Flex>
  </Tooltip>
);

export default NavIconButton;
