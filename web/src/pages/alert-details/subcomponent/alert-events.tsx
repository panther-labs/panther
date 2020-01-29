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

import React, { useState } from 'react';
import JsonViewer from 'Components/json-viewer';
import Panel from 'Components/panel';
import PaginationControls from 'Components/utils/offset-pagination-controls';

interface AlertEventsProps {
  events: string[];
}

const AlertEvents: React.FC<AlertEventsProps> = ({ events }) => {
  // because we are going to use that in PaginationControls we are starting an indexing starting
  // from 1 instead of 0. That's why we are using `eventIndex - 1` when selecting the proper event.
  // Normally the `PaginationControls` are used for displaying pages so they are built with a
  // 1-based indexing in mind
  const [eventIndex, setEventIndex] = useState(1);
  return (
    <Panel
      size="large"
      title="Triggered Events"
      actions={
        <PaginationControls
          page={eventIndex}
          totalPages={events.length}
          onPageChange={setEventIndex}
        />
      }
    >
      <JsonViewer data={JSON.parse(JSON.parse(events[eventIndex - 1]))} />
    </Panel>
  );
};

export default AlertEvents;
