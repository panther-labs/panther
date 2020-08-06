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
import { getCurrentYear } from 'Helpers/utils';
import PantherLogo from 'Assets/panther-logo.svg';

interface AuthPageContainerComposition {
  Caption: React.FC<{ title: string; subtitle?: string }>;
  AltOptions: React.FC;
  Content: React.FC;
}

const Footer: React.FC = ({ children }) => (
  <Flex as="footer" p={26}>
    {children}
  </Flex>
);

/**
 * A component to act as a wrapper for any alternative options that the page can have
 */
const AuthPageContainerAlt: AuthPageContainerComposition['AltOptions'] = ({ children }) => (
  <Footer>
    <Flex color="gray-300" fontSize="small">
      {children}
    </Flex>
  </Footer>
);

const AuthPageContainer: React.FC & AuthPageContainerComposition = ({ children }) => {
  const Copy = (
    <Text as="span" fontSize="small" verticalAlign="text-top" pl={1}>
      ©
    </Text>
  );
  return (
    <SimpleGrid columns={3} height="100vh" backgroundColor="navyblue-600">
      <Flex
        gridColumn="1/2"
        width="100%"
        height="100%"
        direction="column"
        align="center"
        backgroundColor="navyblue-800"
      >
        <Flex
          px={66}
          height="100%"
          align="center"
          direction="column"
          justify="center"
          m="auto"
          data-testid="auth-page-branding"
        >
          <Img src={PantherLogo} alt="Panther Logo" nativeWidth={108} nativeHeight={138} mb={6} />

          <Text lineHeight="relaxed" textAlign="center" mb={4}>
            <strong>Detect Threats with Log Data and Improve Cloud Security Posture</strong>
          </Text>
          <Text lineHeight="relaxed" fontSize="medium" textAlign="center" color="gray-100">
            Designed for any scale
          </Text>
        </Flex>

        <AuthPageContainerAlt>
          Copyright {Copy} {getCurrentYear()} Panther Labs Inc. All Rights Reserved.
        </AuthPageContainerAlt>
      </Flex>

      <Flex
        gridColumn="2/4"
        height="100%"
        align="center"
        direction="column"
        justify="center"
        m="auto"
      >
        {children}
      </Flex>
    </SimpleGrid>
  );
};

/**
 * A compound component for the core contents of the auth page
 */

const AuthPageContainerContent: AuthPageContainerComposition['Content'] = ({ children }) => (
  <Flex
    p={48}
    width={565}
    height="100%"
    align="center"
    direction="column"
    justify="center"
    m="auto"
  >
    <Box backgroundColor="navyblue-400" p={48} width={565}>
      {children}
    </Box>
  </Flex>
);

/**
 * A compound component for the core caption of this auth page
 */
const AuthPageContainerCaption: AuthPageContainerComposition['Caption'] = ({ title, subtitle }) => (
  <Box mb={8} textAlign="center">
    <Heading size="small" color="white-100">
      {title}
    </Heading>

    {subtitle && (
      <Text color="navyblue-100" mt={1}>
        {subtitle}
      </Text>
    )}
  </Box>
);

AuthPageContainer.Caption = AuthPageContainerCaption;
AuthPageContainer.AltOptions = AuthPageContainerAlt;
AuthPageContainer.Content = AuthPageContainerContent;

export default AuthPageContainer;
