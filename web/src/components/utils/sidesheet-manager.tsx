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

/* The component responsible for rendering the actual sidesheets */
import React from 'react';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/sidesheet-context';
import UpdateAwsSourcesSidesheet from 'Components/sidesheets/update-source-sidesheet';
import PolicyBulkUploadSidesheet from 'Components/sidesheets/policy-bulk-upload-sidesheet';
import SelectDestinationSidesheet from 'Components/sidesheets/select-destination-sidesheet';
import AddDestinationSidesheet from 'Components/sidesheets/add-destination-sidesheet';
import UpdateDestinationSidesheet from 'Components/sidesheets/update-destination-sidesheet';
import EditAccountSidesheet from 'Components/sidesheets/edit-account-sidesheet';
import EditUserSidesheet from 'Components/sidesheets/EditUserSidesheet';
import UserInvitationSidesheet from 'Components/sidesheets/user-invitation-sidesheet';

const SidesheetManager: React.FC = () => {
  const { state: sidesheetState } = useSidesheet();
  if (!sidesheetState.sidesheet) {
    return null;
  }

  let Component;
  switch (sidesheetState.sidesheet) {
    case SIDESHEETS.ADD_DESTINATION:
      Component = AddDestinationSidesheet;
      break;
    case SIDESHEETS.UPDATE_DESTINATION:
      Component = UpdateDestinationSidesheet;
      break;
    case SIDESHEETS.SELECT_DESTINATION:
      Component = SelectDestinationSidesheet;
      break;
    case SIDESHEETS.UPDATE_SOURCE:
      Component = UpdateAwsSourcesSidesheet;
      break;
    case SIDESHEETS.POLICY_BULK_UPLOAD:
      Component = PolicyBulkUploadSidesheet;
      break;
    case SIDESHEETS.EDIT_ACCOUNT:
      Component = EditAccountSidesheet;
      break;
    case SIDESHEETS.EDIT_USER:
      Component = EditUserSidesheet;
      break;
    case SIDESHEETS.USER_INVITATION:
      Component = UserInvitationSidesheet;
      break;
    default:
      break;
  }

  return <Component {...sidesheetState.props} />;
};

export default SidesheetManager;
