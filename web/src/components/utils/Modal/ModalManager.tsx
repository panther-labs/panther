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
import DeletePolicyModal from 'Components/modals/DeletePolicyModal';
import DeleteUserModal from 'Components/modals/DeleteUserModal';
import ResetUserPasswordModal from 'Components/modals/ResetUserPasswordModal';
import DeleteComplianceSourceModal from 'Components/modals/DeleteComplianceSourceModal';
import DeleteLogSourceModal from 'Components/modals/DeleteLogSourceModal';
import DeleteDestinationModal from 'Components/modals/DeleteDestinationModal';
import DeleteRuleModal from 'Components/modals/DeleteRuleModal';
import NetworkErrorModal from 'Components/modals/NetworkErrorModal';
import AnalyticsConsentModal from 'Components/modals/AnalyticsConsentModal';
import DeleteTestModal from 'Components/modals/DeleteTestModal';
import { SideSheetProps } from 'pouncejs';

const ModalManager: React.FC = () => {
  const { state: modalState, hideModal } = useModal();

  // There is a particular reason we are using a Ref here and it's for animations. For animations to
  // be properly executed, the *same* component needs to render with `open=true` and `open=false`.
  // When closing a sidesheet then the `sidesheetState.sidesheet` becomes `null`, but we still want
  // to show the *previous* component  with `open=false` so it can properly be animated. That's
  // why we need a Ref.
  const ComponentRef = React.useRef<React.FC<SideSheetProps>>(null);

  switch (modalState.modal) {
    case MODALS.DELETE_COMPLIANCE_SOURCE:
      ComponentRef.current = DeleteComplianceSourceModal;
      break;
    case MODALS.DELETE_LOG_SOURCE:
      ComponentRef.current = DeleteLogSourceModal;
      break;
    case MODALS.DELETE_USER:
      ComponentRef.current = DeleteUserModal;
      break;
    case MODALS.RESET_USER_PASS:
      ComponentRef.current = ResetUserPasswordModal;
      break;
    case MODALS.DELETE_RULE:
      ComponentRef.current = DeleteRuleModal;
      break;
    case MODALS.DELETE_DESTINATION:
      ComponentRef.current = DeleteDestinationModal;
      break;
    case MODALS.NETWORK_ERROR:
      ComponentRef.current = NetworkErrorModal;
      break;
    case MODALS.ANALYTICS_CONSENT:
      ComponentRef.current = AnalyticsConsentModal;
      break;
    case MODALS.DELETE_TEST:
      ComponentRef.current = DeleteTestModal;
      break;
    case MODALS.DELETE_POLICY:
      ComponentRef.current = DeletePolicyModal;
      break;
    default:
      break;
  }

  if (!ComponentRef.current) {
    return null;
  }

  return (
    <ComponentRef.current
      {...modalState.props}
      open={Boolean(modalState.modal)}
      onClose={hideModal}
    />
  );
};

export default ModalManager;
