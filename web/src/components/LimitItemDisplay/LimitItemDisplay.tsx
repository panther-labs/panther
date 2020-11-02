import React from 'react';
import { Flex, Tooltip } from 'pouncejs';

interface LimitItemDisplayProps {
  /**
   * How many items should we show before we limit them
   */
  limit: number;

  /**
   * @ignore
   */
  children: React.ReactNode | React.ReactNode[];
}

const LimitItemDisplay: React.FC<LimitItemDisplayProps> = ({ limit, children }) => {
  const childrenCount = React.Children.count(children);
  if (childrenCount <= limit) {
    return children as any;
  }

  const childrenList = React.Children.toArray(children);
  const displayedChildren = childrenList.slice(0, limit);
  const hiddenChildren = childrenList.slice(limit);

  return (
    <React.Fragment>
      {displayedChildren}
      <Tooltip
        content={
          <Flex direction="column" spacing={1}>
            {hiddenChildren}
          </Flex>
        }
      >
        <Flex
          justify="center"
          align="center"
          width={18}
          height={18}
          backgroundColor="navyblue-200"
          borderRadius="circle"
          fontSize="2x-small"
          fontWeight="medium"
          cursor="default"
        >
          +{childrenCount - limit}
        </Flex>
      </Tooltip>
    </React.Fragment>
  );
};

export default React.memo(LimitItemDisplay);
