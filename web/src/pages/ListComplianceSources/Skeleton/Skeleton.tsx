import TablePlaceholder from 'Components/TablePlaceholder';
import { Card, FadeIn } from 'pouncejs';
import React from 'react';

const Skeleton: React.FC = () => {
  return (
    <FadeIn from="bottom">
      <Card p={9}>
        <TablePlaceholder />
      </Card>
    </FadeIn>
  );
};

export default Skeleton;
