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

import { Breadcrumbs as PounceBreadcrumbs } from 'pouncejs';
import * as React from 'react';
import { isGuid, capitalize, shortenId, isHash } from 'Helpers/utils';
import { Link as RRLink } from 'react-router-dom';
import useRouter from 'Hooks/useRouter';
import ReactDOM from 'react-dom';
import useForceUpdate from 'Hooks/useForceUpdate';

const transformBreadcrumbText = text =>
  isHash(text.toLowerCase()) ? shortenId(text).toLowerCase() : text;

interface BreadcrumbComposition {
  Actions: React.FC;
}

const Breadcrumbs: React.FC & BreadcrumbComposition = () => {
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
      return [];
    }

    return [
      {
        href: '/',
        text: 'Home',
      },
      ...pathKeys.map(key => ({
        href: `${pathname.substr(0, pathname.indexOf(`/${key}/`))}/${key}/`,
        text: decodeURIComponent(key)
          .replace(/([-_])+/g, ' ')
          .split(' ')
          .map(capitalize)
          .map(transformBreadcrumbText)
          .join(' '),
      })),
    ];
  }, [pathname]);

  return <PounceBreadcrumbs items={fragments} as={RRLink} />;
};

const BreadcrumbActions: React.FC = ({ children }) => {
  const getMountPoint = () => document.querySelector('#main-header') as HTMLElement;

  const mountpoint = React.useRef<HTMLElement>(getMountPoint());
  const forceUpdate = useForceUpdate();

  // This may look extremely weird, I know. This is here to prevent race conditions. You see, when
  // a page initially loads the DOM isn't constructed yet by React.
  //
  // This component expects a `main-header` element to be present, which will only be, if React has
  // already rendered the app. Unfortunately, React synchronizes all flushes to the DOM, so in some
  // pages, this component, will be rendered at *the same time* as the entire app.
  //
  // This means  that the mountpoint is `null` since the code in this component executes before the
  // initial flushing to the DOM has happened. To handle  such scenarios, we return early if there
  // is no mountpoint available and "force a re-render" when the DOM has been constructed (we know that
  // since effects happen after the DOM is constructed) which will  guarantee that the
  // mountpoint exists.
  //
  // This behavior only happens when the `<Breadcrumb.Actions>` renders at the same time as the
  // entire app. Sometimes though the app is already loaded when a `<Breadcrumb.Actions>` renders,
  // so to avoid un-necessarily "forcing a re-render", we use the `mountpoint ref` below with
  // certain checks to see if that needs to be done or not
  React.useLayoutEffect(() => {
    // if we originally tried and failed to mount
    if (!mountpoint.current) {
      // calculate the mountpoint element and try once again
      mountpoint.current = getMountPoint();
      forceUpdate();
    }
  }, []);

  return mountpoint.current ? ReactDOM.createPortal(children, mountpoint.current) : null;
};

Breadcrumbs.Actions = React.memo(BreadcrumbActions);

export default Breadcrumbs;
