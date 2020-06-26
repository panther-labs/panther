import React from 'react';
import TablePlaceholder from 'Components/TablePlaceholder';
import { FadeIn } from 'pouncejs';
import Panel from 'Components/Panel';

const Skeleton: React.FC = () => {
  return (
    <FadeIn from="bottom">
      <Panel title="Log Sources">
        <TablePlaceholder />
      </Panel>
    </FadeIn>
  );
};

export default Skeleton;
