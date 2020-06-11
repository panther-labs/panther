/**
 * Copyright (C) 2020 Panther Labs Inc
 *
 * Panther Enterprise is licensed under the terms of a commercial license available from
 * Panther Labs Inc ("Panther Commercial License") by contacting contact@runpanther.com.
 * All use, distribution, and/or modification of this software, whether commercial or non-commercial,
 * falls under the Panther Commercial License to the extent it is permitted.
 */

import React from 'react';
import useRouter from 'Hooks/useRouter';
import queryString from 'query-string';
import omitBy from 'lodash-es/omitBy';

const queryStringOptions = {
  arrayFormat: 'bracket' as const,
  parseNumbers: true,
  parseBooleans: true,
};

function useUrlParams<T extends { [key: string]: any }>() {
  const { history, location } = useRouter();

  /**
   * parses the query params of a URL and returns an object with params in the correct typo
   */
  const urlParams = queryString.parse(location.search, queryStringOptions) as T;

  /**
   * stringifies an object and adds it to the existing query params of a URL
   */
  const updateUrlParams = (params: Partial<T>) => {
    const mergedQueryParams = {
      ...urlParams,
      ...params,
    };

    // Remove any falsy value apart from the value `0` (number) and the value `false` (boolean)
    const cleanedMergedQueryParams = omitBy(
      mergedQueryParams,
      v => !v && !['number', 'boolean'].includes(typeof v)
    );

    history.replace({
      ...location,
      search: queryString.stringify(cleanedMergedQueryParams, queryStringOptions),
    });
  };

  // Cache those values as long as URL parameters are the same
  return React.useMemo(
    () => ({
      urlParams,
      updateUrlParams,
    }),
    [history.location.search]
  );
}

export default useUrlParams;
