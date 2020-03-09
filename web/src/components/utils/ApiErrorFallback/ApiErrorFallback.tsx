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

import React from 'react';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import useRouter from 'Hooks/useRouter';
import Page404 from 'Pages/404';
import Page403 from 'Pages/403';
import Page500 from 'Pages/500';
import urls from 'Source/urls';
import { Redirect } from 'react-router-dom';

export interface LocationErrorState {
  errorType?: string;
}

const ApiErrorFallback: React.FC = ({ children }) => {
  const { location } = useRouter<{}, LocationErrorState>();
  const { showModal, hideModal } = useModal();

  const showNetworkErroModal = React.useCallback(() => {
    showModal({ modal: MODALS.NETWORK_ERROR });
  }, []);

  const hideNetworkErroModal = React.useCallback(() => {
    hideModal();
  }, []);

  React.useEffect(() => {
    window.addEventListener('offline', showNetworkErroModal);
    window.addEventListener('online', hideNetworkErroModal);

    return () => {
      window.removeEventListener('offline', showNetworkErroModal);
      window.removeEventListener('online', hideNetworkErroModal);
    };
  }, []);

  switch (location.state?.errorType) {
    case '401':
      return <Redirect to={urls.account.auth.signIn()} />;
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
