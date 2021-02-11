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

/* The component responsible for rendering the actual modals */
import React from 'react';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';
import DeleteUserModal from 'Components/modals/DeleteUserModal';
import ResetUserPasswordModal from 'Components/modals/ResetUserPasswordModal';
import ReinviteUserModal from 'Components/modals/ReinviteUserModal';
import DeleteComplianceSourceModal from 'Components/modals/DeleteComplianceSourceModal';
import DeleteLogSourceModal from 'Components/modals/DeleteLogSourceModal';
import DeleteDestinationModal from 'Components/modals/DeleteDestinationModal';
import GenericModal from 'Components/modals/GenericModal';
import DeleteDetectionsModal from 'Components/modals/DeleteDetectionsModal';
import NetworkErrorModal from 'Components/modals/NetworkErrorModal';
import AnalyticsConsentModal from 'Components/modals/AnalyticsConsentModal';
import DeleteTestModal from 'Components/modals/DeleteTestModal';
import DeleteGlobalPythonModuleModal from 'Components/modals/DeleteGlobalPythonModuleModal';
import ProfileSettingsModal from 'Components/modals/ProfileSettingsModal';
import DeleteCustomLogModal from 'Components/modals/DeleteCustomLogModal';
import DeleteDataModelModal from 'Components/modals/DeleteDataModelModal';

const ModalManager: React.FC = () => {
  const { state: modalState, hideModal } = useModal();

  let Component;
  switch (modalState.modal) {
    case MODALS.DELETE_COMPLIANCE_SOURCE:
      Component = DeleteComplianceSourceModal;
      break;
    case MODALS.DELETE_LOG_SOURCE:
      Component = DeleteLogSourceModal;
      break;
    case MODALS.DELETE_USER:
      Component = DeleteUserModal;
      break;
    case MODALS.GENERIC_MODAL:
      Component = GenericModal;
      break;
    case MODALS.EDIT_PROFILE_SETTINGS:
      Component = ProfileSettingsModal;
      break;
    case MODALS.RESET_USER_PASS:
      Component = ResetUserPasswordModal;
      break;
    case MODALS.REINVITE_USER:
      Component = ReinviteUserModal;
      break;
    case MODALS.DELETE_DETECTIONS:
      Component = DeleteDetectionsModal;
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
    case MODALS.DELETE_TEST:
      Component = DeleteTestModal;
      break;
    case MODALS.DELETE_GLOBAL_PYTHON_MODULE:
      Component = DeleteGlobalPythonModuleModal;
      break;
    case MODALS.DELETE_CUSTOM_LOG:
      Component = DeleteCustomLogModal;
      break;
    case MODALS.DELETE_DATA_MODEL:
      Component = DeleteDataModelModal;
      break;
    default:
      Component = null;
  }

  if (!Component) {
    return null;
  }

  return <Component {...modalState.props} open={modalState.isVisible} onClose={hideModal} />;
};

export default ModalManager;
