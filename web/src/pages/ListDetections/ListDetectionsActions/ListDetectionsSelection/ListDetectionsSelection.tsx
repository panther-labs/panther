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
import { Box, Button, Flex, Text, Combobox } from 'pouncejs';
import { Detection } from 'Generated/schema';
import { useSelect } from 'Components/utils/SelectContext';
import useModal from 'Hooks/useModal';
import { MODALS } from 'Components/utils/Modal';

const massActions = ['Delete'] as const;
type MassActions = typeof massActions[number];

const ListSavedQueriesSelection: React.FC = () => {
  const { selection, resetSelection } = useSelect<Detection>();
  const [selectedMassAction, setSelectedMassAction] = React.useState<MassActions>(massActions[0]);
  const { showModal } = useModal();

  const handleActionApplication = React.useCallback(() => {
    if (selectedMassAction === 'Delete') {
      showModal({
        modal: MODALS.DELETE_DETECTIONS,
        props: { detections: selection, onSuccess: resetSelection },
      });
    }
  }, [selectedMassAction]);

  return (
    <Flex justify="flex-end" align="center" spacing={4}>
      <Text>{selection.length} Selected</Text>
      <Box width={150}>
        <Combobox
          onChange={setSelectedMassAction}
          items={(massActions as unknown) as MassActions[]}
          value={selectedMassAction}
          label="Mass Action"
        />
      </Box>
      <Button variantColor="violet" onClick={handleActionApplication}>
        Apply
      </Button>
    </Flex>
  );
};

export default React.memo(ListSavedQueriesSelection);
