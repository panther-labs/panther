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
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import useRouter from 'Hooks/useRouter';
import Page404 from 'Pages/404';
import Page403 from 'Pages/403';
import Page500 from 'Pages/500';
import useAuth from 'Hooks/useAuth';

export interface LocationErrorState {
  errorType?: string;
}

const ApiErrorFallback: React.FC = ({ children }) => {
  const { location } = useRouter<Record<string, string | number>, LocationErrorState>();
  const { showModal, hideModal } = useModal();
  const { isAuthenticated, signOut } = useAuth();

  const errorCode = location.state?.errorType;

  const showNetworkErrorModal = React.useCallback(() => {
    showModal({ modal: MODALS.NETWORK_ERROR });
  }, []);

  const hideNetworkErrorModal = React.useCallback(() => {
    hideModal();
  }, []);

  React.useEffect(() => {
    window.addEventListener('offline', showNetworkErrorModal);
    window.addEventListener('online', hideNetworkErrorModal);

    return () => {
      window.removeEventListener('offline', showNetworkErrorModal);
      window.removeEventListener('online', hideNetworkErrorModal);
    };
  }, []);

  // Protect against case where the token has expired during the time the user was navigating
  // and a page refresh hasn't occured
  React.useEffect(() => {
    if ((errorCode === '401' || errorCode === 'UnauthorizedException') && isAuthenticated) {
      signOut();
    }
  }, [errorCode]);

  switch (errorCode) {
    case '404':
      return <Page404 />;
    case '403':
      return <Page403 />;
    case '500':
      return <Page500 />;
    default:
      return children as React.ReactElement;
  }
};

export default ApiErrorFallback;
