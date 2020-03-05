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

/* The component responsible for rendering the actual Modals */
import React from 'react';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/Utils/Modal';
import DeletePolicyModal from 'Components/Modals/delete-policy-modal';
import DeleteUserModal from 'Components/Modals/delete-user-modal';
import ResetUserPasswordModal from 'Components/Modals/reset-user-password-modal';
import DeleteSourceModal from 'Components/Modals/delete-source-modal';
import DeleteDestinationModal from 'Components/Modals/delete-destination-modal';
import DeleteRuleModal from 'Components/Modals/delete-rule-modal';
import NetworkErrorModal from 'Components/Modals/network-error-modal';
import AnalyticsConsentModal from 'Components/Modals/analytics-consent-modal';

const ModalManager: React.FC = () => {
  const { state: modalState } = useModal();
  if (!modalState.modal) {
    return null;
  }
  let Component;
  switch (modalState.modal) {
    case MODALS.DELETE_SOURCE:
      Component = DeleteSourceModal;
      break;
    case MODALS.DELETE_USER:
      Component = DeleteUserModal;
      break;
    case MODALS.RESET_USER_PASS:
      Component = ResetUserPasswordModal;
      break;
    case MODALS.DELETE_RULE:
      Component = DeleteRuleModal;
      break;
    case MODALS.DELETE_DESTINATION:
      Component = DeleteDestinationModal;
      break;
    case MODALS.NETWORK_ERROR:
      Component = NetworkErrorModal;
      break;
    case MODALS.ANALYTICS_CONSENT:
      Component = AnalyticsConsentModal;
      break;
    case MODALS.DELETE_POLICY:
    default:
      Component = DeletePolicyModal;
      break;
  }

  return <Component {...modalState.props} />;
};

export default ModalManager;
