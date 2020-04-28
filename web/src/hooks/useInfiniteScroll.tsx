import React from 'react';

interface UseInfiniteScrollProps {
  // Some sort of "fetching" info of the request.
  loading: boolean;
  // The callback function to execute when the threshold is exceeded.
  onLoadMore: Function;
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
