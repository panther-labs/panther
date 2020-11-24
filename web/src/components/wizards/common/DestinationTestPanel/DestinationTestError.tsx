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
import { Box, Card, Grid, Text } from 'pouncejs';
import { DeliveryResponseFull } from 'Source/graphql/fragments/DeliveryResponseFull.generated';

interface DestinationTestErrorProps {
  response: DeliveryResponseFull;
}

type RowProps = { field: string; value: string | number };

const Row: React.FC<RowProps> = ({ field, value }) => {
  return (
    <React.Fragment>
      <Box as="dt" my="auto">
        {field}
      </Box>
      <Text as="dd" fontWeight="bold">
        {value}
      </Text>
    </React.Fragment>
  );
};

const DestinationTestError: React.FC<DestinationTestErrorProps> = ({
  response: { outputId, dispatchedAt, success, statusCode, message },
}) => {
  return (
    <Card backgroundColor="pink-700" p={6}>
      <Grid
        as="dl"
        wordBreak="break-word"
        templateColumns="max-content 1fr"
        fontSize="medium"
        fontWeight="medium"
        columnGap={4}
        rowGap={4}
      >
        <Row field="Dispatched at" value={dispatchedAt} />
        <Row field="Message" value={message} />
        <Row field="Output ID" value={outputId} />
        <Row field="Status Code" value={statusCode} />
        <Row field="Success" value={success.toString()} />
      </Grid>
    </Card>
  );
};

export default React.memo(DestinationTestError);
