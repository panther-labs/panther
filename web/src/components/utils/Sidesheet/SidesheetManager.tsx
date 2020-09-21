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
import EditUserSidesheet from 'Components/sidesheets/EditUserSidesheet';
import UserInvitationSidesheet from 'Components/sidesheets/UserInvitationSidesheet';

const SidesheetManager: React.FC = () => {
  const { state: sidesheetState, hideSidesheet } = useSidesheet();

  let Component;
  switch (sidesheetState.sidesheet) {
    case SIDESHEETS.EDIT_USER:
      Component = EditUserSidesheet;
      break;
    case SIDESHEETS.USER_INVITATION:
      Component = UserInvitationSidesheet;
      break;
    default:
      Component = null;
  }

  if (!Component) {
    return null;
  }

  return (
    <Component {...sidesheetState.props} open={sidesheetState.isVisible} onClose={hideSidesheet} />
  );
};

export default SidesheetManager;
