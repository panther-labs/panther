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
import { Box, Card, Heading, Text, SimpleGrid, Img, Flex, Link } from 'pouncejs';
import slackLogo from 'Assets/slack-minimal-logo.svg';
import pantherEnterpriseLogo from 'Assets/panther-enterprise-minimal-logo.svg';
import feedbackIcon from 'Assets/illustrations/feedback.svg';
import mailIcon from 'Assets/illustrations/mail.svg';
import withSEO from 'Hoc/withSEO';
import { PANTHER_DOCS_LINK } from 'Source/constants';

type SupportItemPros = {
  title: string;
  subtitle: string;
  imgSrc: string;
  cta: React.ReactNode;
};

export const supportLinks = {
  slack: 'https://slack.runpanther.io',
  email: 'support@runpanther.io',
  productBoard: 'https://portal.productboard.com/runpanther/1-product-portal/tabs/2-in-progress',
  demo: 'https://runpanther.io/request-a-demo/',
};

const SupportItem: React.FC<SupportItemPros> = ({ title, subtitle, imgSrc, cta }) => {
  return (
    <Card backgroundColor="navyblue-500" py={4} px={2} spacing={6}>
      <Flex spacing={6} mx={6}>
        <Flex justify="center" align="center">
          <Flex
            justify="center"
            align="center"
            width={75}
            height={75}
            backgroundColor="navyblue-350"
            borderRadius="circle"
            fontSize="2x-small"
            fontWeight="medium"
          >
            <Img
              src={imgSrc}
              alt="Panther Enterprise logo"
              objectFit="contain"
              nativeHeight={40}
              nativeWidth={40}
            />
          </Flex>
        </Flex>
        <Flex direction="column" spacing={2} justify="space-between" align="space-between">
          <Heading size="small" color="white-100">
            {title}
          </Heading>

          {subtitle && (
            <Text fontSize="small-medium" color="navyblue-100" mt={1}>
              {subtitle}
            </Text>
          )}
          {cta}
        </Flex>
      </Flex>
    </Card>
  );
};

const SupportPage: React.FC = () => {
  return (
    <Card p={9} as="article">
      <Box as="header" mb={10} textAlign="center">
        <Heading size="large" fontWeight="medium">
          Get the support you need
        </Heading>
        <Text fontSize="large" mt={2} color="gray-300">
          You can also visit{' '}
          <Link external href={PANTHER_DOCS_LINK}>
            {' '}
            our documentation
          </Link>{' '}
          if you are facing any problems
        </Text>
      </Box>
      <SimpleGrid columns={2} spacing={6} width={0.9} m="auto">
        <SupportItem
          title="Join our Community Slack"
          subtitle="We’re proud of our growing community in Slack. Join us in supporting each other!"
          imgSrc={slackLogo}
          cta={
            <Link external href={supportLinks.slack}>
              Join Now
            </Link>
          }
        />
        <SupportItem
          title="Send us Product Feedback"
          subtitle="If you found a bug, have an idea for a new feature or simply want to send us your thoughts, don’t hesitate!"
          imgSrc={feedbackIcon}
          cta={
            <Link external href={supportLinks.productBoard}>
              Send your Feedback
            </Link>
          }
        />
        <SupportItem
          title="Send us an E-mail"
          subtitle="If you have any questions about our product or simply want to reach out to us, you can send us an e-mail."
          imgSrc={mailIcon}
          cta={
            <Link external href={`mailto:${supportLinks.email}`}>
              {supportLinks.email}
            </Link>
          }
        />
        <SupportItem
          title="Panther Enterprise"
          subtitle="Get a demo of our enterprise functionality. We'll answer your questions and prepare you for a trial."
          imgSrc={pantherEnterpriseLogo}
          cta={
            <Link external href={supportLinks.demo}>
              Request a demo
            </Link>
          }
        />
      </SimpleGrid>
    </Card>
  );
};

export default withSEO({ title: 'Support' })(SupportPage);
