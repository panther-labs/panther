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
import { Helmet } from 'react-helmet';
import useRouter from 'Hooks/useRouter';
import { RouteComponentProps } from 'react-router';

interface Options {
  title: string | ((routerData: RouteComponentProps<any, undefined>) => string);
}

function withSEO<P>({ title }: Options) {
  return (Component: React.FC<P>) => {
    const ComponentWithSEO: React.FC<P> = props => {
      const routerData = useRouter();

      return (
        <React.Fragment>
          <Helmet titleTemplate="%s | Panther">
            <title>{typeof title === 'string' ? title : title(routerData)}</title>
          </Helmet>
          <Component {...props} />
        </React.Fragment>
      );
    };
    return ComponentWithSEO;
  };
}

export default withSEO;
