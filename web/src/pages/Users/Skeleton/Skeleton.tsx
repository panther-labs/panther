import { FadeIn } from 'pouncejs';
import TablePlaceholder from 'Components/TablePlaceholder';
import React from 'react';
import Panel from 'Components/Panel';

const Skeleton: React.FC = () => {
  return (
    <FadeIn from="bottom">
      <Panel title="Users">
        <TablePlaceholder />
      </Panel>
    </FadeIn>
  );
};

export default Skeleton;
