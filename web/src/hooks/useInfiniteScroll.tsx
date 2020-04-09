/**
 * A Cloud-Native SIEM for the Modern Security Team
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
import { useInfiniteScroll } from 'react-infinite-scroll-hook';

interface UseInfiniteScrollHookProps {
  loading: boolean;

  // The callback function to execute when we want to load more data.
  onLoadMore: Function;
}

// This hook builds upon https://www.npmjs.com/package/react-infinite-scroll-hook
const useInfiniteScrollHook = ({ loading, onLoadMore }: UseInfiniteScrollHookProps) => {
  const [hasNextPage, setHasNextPage] = React.useState(true);
  const infiniteRef = useInfiniteScroll<HTMLDivElement>({
    loading,
    hasNextPage,
    onLoadMore,
    scrollContainer: 'window', // Set the scroll container to 'window' since 'parent' is a bit buggy
    checkInterval: 800, // The default is 200 which seems a bit too quick
  });

  return { infiniteRef, setHasNextPage };
};

export default useInfiniteScrollHook;
