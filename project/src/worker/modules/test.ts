// SPDX-FileCopyrightText: 2025 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import nacl from 'tweetnacl/nacl-fast';
import { Module, ModuleObject } from '../types'

export interface TestModuleObject extends ModuleObject {
    toBase64: (str: string) => string
}

const TestModule: Module<TestModuleObject> = {

    init: (config, cb) => {
        let myTest = {};

        cb();

        return {
            removeClient: (clientId) => {
                console.log('Remove client', clientId);
            },
            execCommand: (clientId, obj, cb) => {
                console.log('Exex command', clientId, obj);
                cb();
            },
            toBase64: (str) => {
                return nacl.util.encodeBase64(nacl.util.decodeUTF8(str));
            }
        }
    }


};

export { TestModule }
