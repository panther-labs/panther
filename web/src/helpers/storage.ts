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

interface StorageShape {
  getItem: (key: string) => string | null;
  removeItem: (key: string) => void;
  setItem: (key: string, item: string) => void;
  clear: () => void;
}

class Storage {
  storageInstance: StorageShape;

  constructor(storageInstance: StorageShape) {
    this.storageInstance = storageInstance;
  }

  /**
   * Stores data in the storage
   *
   * @param key The key to store the data under
   * @param data The data to store
   */
  write(key: string, data: any) {
    const storedShape = data instanceof Object ? JSON.stringify(data) : data;
    this.storageInstance.setItem(key, storedShape);
  }

  /**
   * Retrieves data from the storage
   *
   * @param key The key to read
   * @returns the data matching this key
   */
  read<T = string>(key: string): T {
    const data = this.storageInstance.getItem(key);
    if (data === null) {
      return null;
    }

    try {
      return JSON.parse(this.storageInstance.getItem(key)) as T;
    } catch (e) {
      return (data as unknown) as T;
    }
  }

  /**
   *
   * @param key The key to delete
   * @returns void
   */
  delete(key: string) {
    this.storageInstance.removeItem(key);
  }

  /**
   * Clears the storage from all of its keys
   */
  clear() {
    this.storageInstance.clear();
  }
}

const local = new Storage(localStorage);
const session = new Storage(sessionStorage);

const storage = { local, session };

export default storage;
