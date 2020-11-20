/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';

const useHover = () => {
  const [isHovering, setHovering] = React.useState(false);

  const handleMouseEnter = React.useCallback(() => {
    setHovering(true);
  }, [setHovering]);

  const handleMouseLeave = React.useCallback(() => {
    setHovering(false);
  }, [setHovering]);

  return React.useMemo(
    () => ({
      isHovering,
      handlers: {
        onMouseEnter: handleMouseEnter,
        onMouseLeave: handleMouseLeave,
      },
    }),
    [isHovering, handleMouseEnter, handleMouseLeave]
  );
};

export default useHover;
