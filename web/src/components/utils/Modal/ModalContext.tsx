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
import { DeletePolicyModalProps } from 'Components/modals/DeletePolicyModal';
import { DeleteUserModalProps } from 'Components/modals/DeleteUserModal';
import { ResetUserPasswordProps } from 'Components/modals/ResetUserPasswordModal';
import { DeleteComplianceSourceModalProps } from 'Components/modals/DeleteComplianceSourceModal';
import { DeleteLogSourceModalProps } from 'Components/modals/DeleteLogSourceModal';
import { DeleteDestinationModalProps } from 'Components/modals/DeleteDestinationModal';
import { GenericModalProps } from 'Components/modals/GenericModal';
import { DeleteRuleModalProps } from 'Components/modals/DeleteRuleModal';
import { DeleteTestModalProps } from 'Components/modals/DeleteTestModal';
import { DeleteGlobalPythonModuleModalProps } from 'Components/modals/DeleteGlobalPythonModuleModal';
import { AnalyticsConsentModalProps } from 'Components/modals/AnalyticsConsentModal';
import { DeleteCustomLogModalProps } from 'Components/modals/DeleteCustomLogModal';
import { DeleteDataModelModalProps } from 'Components/modals/DeleteDataModelModal';

const SHOW_MODAL = 'SHOW_MODAL';
const HIDE_MODAL = 'HIDE_MODAL';

/* The available list of modals to dispatch */
export enum MODALS {
  DELETE_POLICY = 'DELETE_POLICY',
  DELETE_CUSTOM_LOG = 'DELETE_CUSTOM_LOG',
  DELETE_DATA_MODEL = 'DELETE_DATA_MODEL',
  DELETE_RULE = 'DELETE_RULE',
  DELETE_GLOBAL_PYTHON_MODULE = 'DELETE_GLOBAL_PYTHON_MODULE',
  DELETE_USER = 'DELETE_USER',
  DELETE_TEST = 'DELETE_TEST',
  GENERIC_MODAL = 'GENERIC_MODAL',
  EDIT_PROFILE_SETTINGS = 'EDIT_PROFILE_SETTINGS',
  RESET_USER_PASS = 'RESET_USER_PASS',
  DELETE_COMPLIANCE_SOURCE = 'DELETE_COMPLIANCE_SOURCE',
  DELETE_LOG_SOURCE = 'DELETE_LOG_SOURCE',
  DELETE_DESTINATION = 'DELETE_DESTINATION',
  NETWORK_ERROR = 'NETWORK_ERROR',
  ANALYTICS_CONSENT = 'ANALYTICS_CONSENT',
}

type OmitControlledProps<T> = Omit<T, 'open' | 'onClose'>;

/* The shape of the reducer state */
interface ModalStateShape {
  modal: keyof typeof MODALS | null;
  props: { [key: string]: any };
  isVisible: boolean;
}

/* Show delete policy modal */
interface ShowPolicyModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_POLICY;
    props: OmitControlledProps<DeletePolicyModalProps>;
  };
}
interface ShowCustomLogModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_CUSTOM_LOG;
    props: OmitControlledProps<DeleteCustomLogModalProps>;
  };
}

interface ShowGenericModal {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.GENERIC_MODAL;
    props: OmitControlledProps<GenericModalProps>;
  };
}

/* 2nd action */
interface HideModalAction {
  type: typeof HIDE_MODAL;
}
/* Delete Global Module action */
interface ShowGlobalPythonModuleModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_GLOBAL_PYTHON_MODULE;
    props: OmitControlledProps<DeleteGlobalPythonModuleModalProps>;
  };
}
/* Delete User action */
interface ShowDeleteUserModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_USER;
    props: OmitControlledProps<DeleteUserModalProps>;
  };
}

/* Reset user password */
interface ShowResetUserPasswordModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.RESET_USER_PASS;
    props: OmitControlledProps<ResetUserPasswordProps>;
  };
}

interface ShowDeleteTestModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_TEST;
    props: OmitControlledProps<DeleteTestModalProps>;
  };
}

interface ShowDeleteDataModelModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_DATA_MODEL;
    props: OmitControlledProps<DeleteDataModelModalProps>;
  };
}

/* Delete Compliance Source action */
interface ShowDeleteComplianceSourceModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_COMPLIANCE_SOURCE;
    props: OmitControlledProps<DeleteComplianceSourceModalProps>;
  };
}

/* Delete Log Source action */
interface ShowDeleteLogSourceModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_LOG_SOURCE;
    props: OmitControlledProps<DeleteLogSourceModalProps>;
  };
}

/* Opens the modal that allows the user to update info & change password */
interface ShowProfileSettingsModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.EDIT_PROFILE_SETTINGS;
  };
}

/* 1st action */
interface ShowDeleteRuleModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_RULE;
    props: OmitControlledProps<DeleteRuleModalProps>;
  };
}

/* Delete Destination action */
interface ShowDeleteDestinationModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.DELETE_DESTINATION;
    props: OmitControlledProps<DeleteDestinationModalProps>;
  };
}

/* Delete Destination action */
interface ShowNetworkErrorModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.NETWORK_ERROR;
  };
}

/* Show analytics consent options action */
interface ShowAnalyticsConsentModalAction {
  type: typeof SHOW_MODAL;
  payload: {
    modal: MODALS.ANALYTICS_CONSENT;
    props?: OmitControlledProps<AnalyticsConsentModalProps>;
  };
}

/* The available actions that can be dispatched */
type ModalStateAction =
  | ShowGenericModal
  | ShowDeleteComplianceSourceModalAction
  | ShowCustomLogModalAction
  | ShowDeleteLogSourceModalAction
  | ShowDeleteDataModelModalAction
  | ShowGlobalPythonModuleModalAction
  | ShowDeleteUserModalAction
  | ShowDeleteTestModalAction
  | ShowProfileSettingsModalAction
  | ShowResetUserPasswordModalAction
  | ShowPolicyModalAction
  | ShowDeleteRuleModalAction
  | ShowDeleteDestinationModalAction
  | ShowNetworkErrorModalAction
  | ShowAnalyticsConsentModalAction
  | HideModalAction;

/* initial state of the reducer */
const initialState: ModalStateShape = {
  modal: null,
  props: {},
  isVisible: false,
};

const modalReducer = (state: ModalStateShape, action: ModalStateAction) => {
  switch (action.type) {
    case SHOW_MODAL:
      return {
        modal: action.payload.modal,
        props: 'props' in action.payload ? action.payload.props : {},
        isVisible: true,
      };
    case HIDE_MODAL:
      return { ...state, isVisible: false };
    default:
      return state;
  }
};

interface ModalContextValue {
  state: ModalStateShape;
  showModal: (input: Exclude<ModalStateAction, HideModalAction>['payload']) => void;
  hideModal: () => void;
}

/* Context that will hold the `state` and `dispatch` */
export const ModalContext = React.createContext<ModalContextValue>(undefined);

/* A enhanced version of the context provider */
export const ModalProvider: React.FC = ({ children }) => {
  const [state, dispatch] = React.useReducer<React.Reducer<ModalStateShape, ModalStateAction>>(
    modalReducer,
    initialState
  );

  // for perf reasons we only want to re-render on state updates
  const contextValue = React.useMemo(
    () => ({
      state,
      hideModal: () => dispatch({ type: 'HIDE_MODAL' }),
      showModal: ({ modal, props }) => dispatch({ type: 'SHOW_MODAL', payload: { modal, props } }),
    }),
    [state]
  );

  // make the `state` and `dispatch` available to the components
  return <ModalContext.Provider value={contextValue}>{children}</ModalContext.Provider>;
};
