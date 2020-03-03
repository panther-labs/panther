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
import { UpdateSourceSidesheetProps } from 'Components/sidesheets/update-source-sidesheet';
import { AddDestinationSidesheetProps } from 'Components/sidesheets/add-destination-sidesheet';
import { UpdateDestinationSidesheetProps } from 'Components/sidesheets/update-destination-sidesheet';
import { PolicyBulkUploadSideSheetProps } from 'Components/sidesheets/policy-bulk-upload-sidesheet';
import { EditUserSidesheetProps } from 'Components/sidesheets/EditUserSidesheet';

const SHOW_SIDESHEET = 'SHOW_SIDESHEET';
const HIDE_SIDESHEET = 'HIDE_SIDESHEET';

/* The available list of sidesheets to dispatch */
export enum SIDESHEETS {
  UPDATE_SOURCE = 'UPDATE_SOURCE',
  POLICY_BULK_UPLOAD = 'POLICY_BULK_UPLOAD',
  SELECT_DESTINATION = 'SELECT_DESTINATION',
  ADD_DESTINATION = 'ADD_DESTINATION',
  UPDATE_DESTINATION = 'UPDATE_DESTINATION',
  EDIT_ACCOUNT = 'EDIT_ACCOUNT',
  EDIT_USER = 'EDIT_USER',
  USER_INVITATION = 'USER_INVITATION',
}

/* The shape of the reducer state */
interface SidesheetStateShape {
  sidesheet: keyof typeof SIDESHEETS | null;
  props?: { [key: string]: any };
}

/* 1st action */
interface UpdateSourceSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.UPDATE_SOURCE;
    props: UpdateSourceSidesheetProps;
  };
}

interface SelectDestinationSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.SELECT_DESTINATION;
  };
}

interface AddDestinationSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.ADD_DESTINATION;
    props: AddDestinationSidesheetProps;
  };
}

interface UpdateDestinationSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.UPDATE_DESTINATION;
    props: UpdateDestinationSidesheetProps;
  };
}

interface HideSidesheetAction {
  type: typeof HIDE_SIDESHEET;
}

/* Bulk upload policies action */
interface PolicyBulkUploadSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.POLICY_BULK_UPLOAD;
    props: PolicyBulkUploadSideSheetProps;
  };
}

interface EditAccountSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.EDIT_ACCOUNT;
  };
}

interface EditUserSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.EDIT_USER;
    props: EditUserSidesheetProps;
  };
}

interface UserInvitationSideSheetAction {
  type: typeof SHOW_SIDESHEET;
  payload: {
    sidesheet: SIDESHEETS.USER_INVITATION;
  };
}

/* The available actions that can be dispatched */
type SidesheetStateAction =
  | UpdateSourceSideSheetAction
  | PolicyBulkUploadSideSheetAction
  | SelectDestinationSideSheetAction
  | AddDestinationSideSheetAction
  | UpdateDestinationSideSheetAction
  | EditAccountSideSheetAction
  | EditUserSideSheetAction
  | UserInvitationSideSheetAction
  | HideSidesheetAction;

/* initial state of the reducer */
const initialState: SidesheetStateShape = {
  sidesheet: null,
  props: {},
};

const sidesheetReducer = (state: SidesheetStateShape, action: SidesheetStateAction) => {
  switch (action.type) {
    case SHOW_SIDESHEET:
      return {
        sidesheet: action.payload.sidesheet,
        props: 'props' in action.payload ? action.payload.props : {},
      };
    case HIDE_SIDESHEET:
      return { sidesheet: null, props: {} };
    default:
      return state;
  }
};

interface SidesheetContextValue {
  state: SidesheetStateShape;
  showSidesheet: (input: Exclude<SidesheetStateAction, HideSidesheetAction>['payload']) => void;
  hideSidesheet: () => void;
}

/* Context that will hold the `state` and `dispatch` */
export const SidesheetContext = React.createContext<SidesheetContextValue>(undefined);

/* A enhanced version of the context provider */
export const SidesheetProvider: React.FC = ({ children }) => {
  const [state, dispatch] = React.useReducer<
    React.Reducer<SidesheetStateShape, SidesheetStateAction>
  >(sidesheetReducer, initialState);

  // for perf reasons we only want to re-render on state updates
  const contextValue = React.useMemo(
    () => ({
      state,
      hideSidesheet: () => dispatch({ type: 'HIDE_SIDESHEET' }),
      showSidesheet: ({ sidesheet, props }) =>
        dispatch({ type: 'SHOW_SIDESHEET', payload: { sidesheet, props } }),
    }),
    [state]
  );

  // make the `state` and `dispatch` available to the components
  return <SidesheetContext.Provider value={contextValue}>{children}</SidesheetContext.Provider>;
};
