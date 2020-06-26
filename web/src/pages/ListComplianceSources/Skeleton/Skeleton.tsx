import TablePlaceholder from 'Components/TablePlaceholder';
import { FadeIn } from 'pouncejs';
import Panel from 'Components/Panel';
import React from 'react';

const Skeleton: React.FC = () => {
  return (
    <FadeIn from="bottom">
      <Panel title="Connected Accounts">
        <TablePlaceholder />
      </Panel>
    </FadeIn>
  );
};

export default Skeleton;
