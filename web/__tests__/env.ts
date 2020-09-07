import path from 'path';
import { loadDotEnvVars } from '../scripts/utils';

loadDotEnvVars(path.resolve(__dirname, '.env.test'));
