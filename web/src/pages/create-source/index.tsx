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

import React from 'react';
import queryString from 'query-string';
import { INTEGRATION_TYPES } from 'Source/constants';
import useRouter from 'Hooks/useRouter';
import CreateInfraSource from './subcomponents/create-infra-source';
import CreateLogSource from './subcomponents/create-log-source';

const CreateSourcePage: React.FC = () => {
  const { location } = useRouter();
  const { type } = queryString.parse(location.search) as { type: INTEGRATION_TYPES };
  return type === INTEGRATION_TYPES.AWS_INFRA ? <CreateInfraSource /> : <CreateLogSource />;
};

export default CreateSourcePage;
