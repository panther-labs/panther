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
import { Flex, Box, Text, Heading, SimpleGrid, Img } from 'pouncejs';
import PantherLogoWhite from 'Assets/panther-minimal-logo.svg';

interface AuthPageContainerComposition {
  Caption: React.FC<{ title: string; subtitle?: string }>;
  AltOptions: React.FC;
}

const AuthPageContainer: React.FC & AuthPageContainerComposition = ({ children }) => {
  return (
    <SimpleGrid columns={3} height="100vh" backgroundColor="navyblue-600">
      <Flex
        gridColumn="1/2"
        width="100%"
        height="100%"
        direction="column"
        justify="center"
        align="center"
        backgroundColor="navyblue-700"
      >
        <Img src={PantherLogoWhite} alt="Panther Logo" nativeWidth={54} nativeHeight={54} mb={6} />
        <Heading size="x-large" mb={3} textAlign="center">
          Panther Community Edition
        </Heading>
        <Text lineHeight="relaxed" textAlign="center">
          Detect threats with log data and improve cloud security posture
          <br />
          Designed for any scale
        </Text>
      </Flex>
      <Flex gridColumn="2/4" justify="center" align="center">
        <Box width={460}>{children}</Box>
      </Flex>
    </SimpleGrid>
  );
};

/**
 * A compound component for the core caption of this auth page
 */
const AuthPageContainerCaption: AuthPageContainerComposition['Caption'] = ({ title, subtitle }) => (
  <Box mb={8}>
    <Heading size="large">{title}</Heading>
    {subtitle && (
      <Text color="gray-300" mt={2}>
        {subtitle}
      </Text>
    )}
  </Box>
);

/**
 * A compounet component to act as a wrapper for any alternative options that the page can have
 */
const AuthPageContainerAlt: AuthPageContainerComposition['AltOptions'] = ({ children }) => (
  <Box position="absolute" right={10} top={10} color="gray-300" fontSize="medium">
    {children}
  </Box>
);

AuthPageContainer.Caption = AuthPageContainerCaption;
AuthPageContainer.AltOptions = AuthPageContainerAlt;

export default AuthPageContainer;
