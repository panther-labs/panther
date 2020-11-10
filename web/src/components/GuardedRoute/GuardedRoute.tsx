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
import useAuth from 'Hooks/useAuth';
import { Location } from 'history';
import { Redirect, Route, RouteProps } from 'react-router-dom';
import urls from 'Source/urls';
import useRouter from 'Hooks/useRouter';

interface GuardedRouteProps extends RouteProps {
  limitAccessTo: 'anonymous' | 'authenticated';
}

/**
 * Makes sure to render a Route only if the guarded restriction is satisfied. Else we just render
 * a redirect to a URL according to the restriction type
 */
const GuardedRoute: React.FC<GuardedRouteProps> = ({ limitAccessTo, ...rest }) => {
  const { isAuthenticated } = useAuth();
  const { location } = useRouter<Record<string, string | number>, { referrer: Location }>();

  if (
    (limitAccessTo === 'anonymous' && !isAuthenticated) ||
    (limitAccessTo === 'authenticated' && isAuthenticated)
  ) {
    return <Route {...rest} />;
  }

  // Ok so, the following lines are not as simple as they appear.
  let redirectData: { pathname: string; state: { referrer: Location } };

  // This one simply redirects the user to the SignIn page and adds a referrer page to return
  // back to when the user becomes authenticated. It's as simple as it appears. User went to access
  // a protected page and the page went "buddy gimme some creds first"
  if (limitAccessTo === 'authenticated') {
    redirectData = {
      pathname: urls.account.auth.signIn(),
      state: { ...location.state, referrer: location },
    };
    // This one means that an authenticated user is trying to access an anonymous only page. What we
    // do is redirect them to a referrer page if it existed or just the base page. Now why the
    // referrer? Because when the user signs in, he's still in the SignIn page which suddenly
    // denied access to him because the "guarded-route" said "hey buddy you are now authenticated,
    // you can't be accessing the SignIn page". The user said though "but I literally just signed-
    // in, where else could I be?!". Because both of these people are right, we redirect the user
    // to the referrer *if it exists* (a.k.a. if he just signed in) or the home page if he's just
    // plain stupid and manually went to the SignIn page through the URL bar (in which case no
    // referrer will exist)
  } else {
    redirectData = {
      ...location.state?.referrer,
      pathname: location?.state?.referrer?.pathname || '/',
      state: undefined,
    };
  }

  return <Redirect to={redirectData} push={false} />;
};

export default GuardedRoute;
