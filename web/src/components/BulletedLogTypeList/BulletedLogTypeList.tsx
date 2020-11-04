import React from 'react';
import { Flex } from 'pouncejs';
import LimitItemDisplay from 'Components/LimitItemDisplay/LimitItemDisplay';
import BulletedLogType from 'Components/BulletedLogType';

interface BulletedLogTypeListProps {
  logTypes: string[];
  limit?: number;
}

const BulletedLogTypeList: React.FC<BulletedLogTypeListProps> = ({ logTypes, limit = 1000 }) => {
  return (
    <Flex align="center" spacing={2} flexWrap="wrap">
      <LimitItemDisplay limit={limit}>
        {logTypes.map(logType => (
          <BulletedLogType key={logType} logType={logType} />
        ))}
      </LimitItemDisplay>
    </Flex>
  );
};

export default BulletedLogTypeList;
