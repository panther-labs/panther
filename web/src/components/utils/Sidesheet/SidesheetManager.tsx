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

/* The component responsible for rendering the actual sidesheets */
import React from 'react';
import useSidesheet from 'Hooks/useSidesheet';
import { SIDESHEETS } from 'Components/utils/Sidesheet';
import { SideSheetProps } from 'pouncejs';
import PolicyBulkUploadSidesheet from 'Components/sidesheets/PolicyBulkUploadSidesheet';
import SelectDestinationSidesheet from 'Components/sidesheets/SelectDestinationSidesheet';
import AddDestinationSidesheet from 'Components/sidesheets/AddDestinationSidesheet';
import UpdateDestinationSidesheet from 'Components/sidesheets/UpdateDestinationSidesheet';
import EditAccountSidesheet from 'Components/sidesheets/EditAccountSidesheet';
import EditUserSidesheet from 'Components/sidesheets/EditUserSidesheet';
import UserInvitationSidesheet from 'Components/sidesheets/UserInvitationSidesheet';

const SidesheetManager: React.FC = () => {
  const { state: sidesheetState, hideSidesheet } = useSidesheet();

  // There is a particular reason we are using a Ref here and it's for animations. For animations to
  // be properly executed, the *same* component needs to render with `open=true` and `open=false`.
  // When closing a sidesheet then the `sidesheetState.sidesheet` becomes `null`, but we still want
  // to show the *previous* component  with `open=false` so it can properly be animated. That's
  // why we need a Ref.
  const ComponentRef = React.useRef<React.FC<SideSheetProps>>(null);

  switch (sidesheetState.sidesheet) {
    case SIDESHEETS.ADD_DESTINATION:
      ComponentRef.current = AddDestinationSidesheet;
      break;
    case SIDESHEETS.UPDATE_DESTINATION:
      ComponentRef.current = UpdateDestinationSidesheet;
      break;
    case SIDESHEETS.SELECT_DESTINATION:
      ComponentRef.current = SelectDestinationSidesheet;
      break;
    case SIDESHEETS.POLICY_BULK_UPLOAD:
      ComponentRef.current = PolicyBulkUploadSidesheet;
      break;
    case SIDESHEETS.EDIT_ACCOUNT:
      ComponentRef.current = EditAccountSidesheet;
      break;
    case SIDESHEETS.EDIT_USER:
      ComponentRef.current = EditUserSidesheet;
      break;
    case SIDESHEETS.USER_INVITATION:
      ComponentRef.current = UserInvitationSidesheet;
      break;
    default:
      break;
  }

  if (!ComponentRef.current) {
    return null;
  }

  return (
    <ComponentRef.current
      {...sidesheetState.props}
      open={Boolean(sidesheetState.sidesheet)}
      onClose={hideSidesheet}
    />
  );
};

export default SidesheetManager;
