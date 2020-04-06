/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
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

import { Breadcrumbs as PounceBreadcrumbs } from 'pouncejs';
import * as React from 'react';
import { isGuid, capitalize } from 'Helpers/utils';
import { Link } from 'react-router-dom';
import useRouter from 'Hooks/useRouter';

// @HELP_WANTED
// resource names can get super big. We wanna guard against that. Normally we would just say
// that the name should be truncated to the width it fits in, but there is a problem in our case.
// What happens if we go to "/policies/<BIG_TEXT>/edit"? You would be seeing
// "/policies/<BIG_TEXT....>" and you would never be able to see that last part of the breadcrumbs
// that contains the word "edit". To guard against that, we are saying that the biggest breacrumb
// will be a fixed amount of px so that there is *always* space for some other stuff. This is a
// *hardcoded behaviour* meant to guard us against the resource & policy details pages and the number
// assigned to `maxWidth` is special so thaat it can cover our possible breadcrumb combinations when
// a breadcrumb contains a resourceID or a policyID within it. I can't think of any other solution
// that can fit our usecase that doesn't involve complex JS calculations, so please help out
const widthSentinelStyles = {
  display: 'block',
  maxWidth: '450px',
  whiteSpace: 'nowrap' as const,
  overflow: 'hidden' as const,
  textOverflow: 'ellipsis' as const,
};

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
        <Link to={item.href} style={widthSentinelStyles}>
          {item.text}
        </Link>
      )}
    />
  );
};

export default Breadcrumbs;
