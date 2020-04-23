import React from 'react';
import { SEVERITY_COLOR_MAP } from 'Source/constants';
import { Badge } from 'pouncejs';
import { SeverityEnum } from 'Generated/schema';

interface SeverityBadgeProps {
  severity: SeverityEnum;
}

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  return <Badge color={SEVERITY_COLOR_MAP[severity]}>{severity}</Badge>;
};

export default SeverityBadge;
