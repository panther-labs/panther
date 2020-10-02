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
import withSEO from 'Hoc/withSEO';
import useRouter from 'Hooks/useRouter';
import Page404 from 'Pages/404';
import { EventEnum, SrcEnum, trackEvent } from 'Helpers/analytics';
import CreateS3LogSource from './CreateS3LogSource';
import CreateSqsSource from './CreateSqsLogSource';

const CreateLogSource: React.FC = () => {
  const {
    match: {
      params: { type },
    },
  } = useRouter();

  switch (type) {
    case 'S3':
      trackEvent({ event: EventEnum.PickedLogSource, src: SrcEnum.LogSources, ctx: 'S3' });
      return <CreateS3LogSource />;
    case 'SQS':
      trackEvent({ event: EventEnum.PickedLogSource, src: SrcEnum.LogSources, ctx: 'SQS' });
      return <CreateSqsSource />;
    default:
      return <Page404 />;
  }
};

export default withSEO({ title: 'New Log Analysis Source' })(CreateLogSource);
