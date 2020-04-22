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

import { Box, Breadcrumbs as PounceBreadcrumbs } from 'pouncejs';
import * as React from 'react';
import { isGuid, capitalize, shortenId, isHash } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';
import useRouter from 'Hooks/useRouter';

const transformBreadcrumbText = text => (isHash(text) ? shortenId(text) : text);

const Breadcrumbs: React.FC = () => {
  const {
    location: { pathname },
  } = useRouter();

  const fragments = React.useMemo(() => {
    // split by slash and remove empty-splitted values caused by trailing slashes. We also don't
    // want to display the UUIDs as part of the breadcrumbs (which unfortunately exist in the URL)
    const pathKeys = pathname.split('/').filter(fragment => !!fragment && !isGuid(fragment));

    // return the label (what to show) and the uri of each fragment. The URI is constructed by
    // taking the existing path and removing whatever is after each pathKey (only keeping whatever
    // is before-and-including our key). The key is essentially the URL path itself just prettified
    // for displat
    if (!pathKeys.length) {
      return [
        {
          href: '/',
          text: 'Home',
        },
      ];
    }

    return pathKeys.map(key => ({
      href: `${pathname.substr(0, pathname.indexOf(`/${key}/`))}/${key}/`,
      text: decodeURIComponent(key)
        .replace(/([-_])+/g, ' ')
        .split(' ')
        .map(capitalize)
        .join(' '),
    }));
  }, [pathname]);

  return (
    <PounceBreadcrumbs
      items={fragments}
      itemRenderer={item => (
        <Box as={RRLink} to={item.href} display="block" maxWidth="450px" truncated>
          {transformBreadcrumbText(item.text)}
        </Box>
      )}
    />
  );
};

export default Breadcrumbs;
