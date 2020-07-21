/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import { Flex, Img, Tooltip } from 'pouncejs';

type LogSourceTypeProps = {
  name: string;
  logo: any;
};

const LogSourceType: React.FC<LogSourceTypeProps> = ({ name, logo }) => {
  return (
    <Flex justify="start" align="center">
      <Tooltip content={name}>
        <Img
          src={logo}
          alt={name}
          objectFit="contain"
          nativeHeight={48}
          nativeWidth={48}
          my={-2}
          px={1}
        />
      </Tooltip>
    </Flex>
  );
};

export default React.memo(LogSourceType);
