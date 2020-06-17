/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import React from 'react';

interface UseInfiniteScrollProps {
  // Some sort of "fetching" info of the request.
  loading: boolean;
  // The callback function to execute when the threshold is exceeded.
  onLoadMore: () => void;
  // Maximum distance to bottom of the window/parent to trigger the callback. Default is 150.
  threshold?: number;
  // May be `"window"` or `"parent"`. Default is `"window"`. If you want to use a scrollable parent for the infinite list, use `"parent"`.
  scrollContainer?: 'window' | 'parent';
}

function useInfiniteScroll<T extends Element>({
  loading,
  onLoadMore,
  threshold = 0,
  scrollContainer = 'window',
}: UseInfiniteScrollProps) {
  const sentinelRef = React.useRef<T>(null);
  const prevY = React.useRef(10000000);

  const callback = React.useCallback(
    entries => {
      entries.forEach(entry => {
        if (
          // is coming into viewport (i.e. it's not in the "leaving" phase)
          entry.isIntersecting &&
          // we approached it while scrolling downwards (not upwards)
          prevY.current >= entry.boundingClientRect.y &&
          // we are not already loading more
          !loading
        ) {
          onLoadMore();
        }

        // Only update the prevY when the sentinel is not in the viewport (since if it's in the
        // viewport, we want to keep loading & loading until it gets out of the viewport)
        if (!entry.intersectionRatio) {
          prevY.current = entry.boundingClientRect.y;
        }
      });
    },
    [loading, onLoadMore]
  );

  // eslint-disable-next-line consistent-return
  React.useEffect(() => {
    const sentinelNode = sentinelRef.current;
    if (sentinelNode) {
      const observer = new IntersectionObserver(callback, {
        root: scrollContainer === 'window' ? null : sentinelNode.parentElement,
        threshold: 0,
        rootMargin: `0px 0px ${threshold}px 0px`,
      });
      observer.observe(sentinelNode);

      return () => observer.disconnect();
    }
  }, [sentinelRef.current, threshold, scrollContainer, callback]);

  return { sentinelRef };
}

export default useInfiniteScroll;
