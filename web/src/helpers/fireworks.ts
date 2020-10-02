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

// Cause baby you're a firework, come on show em what you're worth
// https://www.youtube.com/watch?v=QGJuMBdaqIw
const shootFireworks = ({ duration = 3500 }: { duration?: number } = {}) => {
  // Lazy load it since we are only gonna need it once per installation
  import(/* webpackChunkName: "canvas-confetti" */ 'canvas-confetti').then(
    ({ default: confetti }) => {
      const shootRandomFirework = (side: 'left' | 'right') => {
        confetti({
          particleCount: 50,
          origin: {
            x: Math.random() * 0.2 + (side === 'left' ? 0.1 : 0.7),
            y: Math.random() - 0.2,
          },
          spread: 240,
        });
      };

      window.requestIdleCallback(() => {
        const interval = setInterval(() => {
          requestAnimationFrame(() => shootRandomFirework('left'));
          requestAnimationFrame(() => shootRandomFirework('right'));
        }, 250);

        setTimeout(() => clearInterval(interval), duration);
      });
    }
  );
};

export default shootFireworks;
