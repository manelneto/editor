// SPDX-FileCopyrightText: 2023 XWiki CryptPad Team <contact@cryptpad.org> and contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/*
 * You can override the configurable values from this file.
 * The recommended method is to make a copy of this file (/customize.dist/application_config.js)
   in a 'customize' directory (/customize/application_config.js).
 * If you want to check all the configurable values, you can open the internal configuration file
   but you should not change it directly (/common/application_config_internal.js)
*/

(() => {
const factory = (AppConfig) => {
    AppConfig.availablePadTypes = ['drive', 'pad', 'file', 'contacts'];
    AppConfig.availableLanguages = ['en'];
    AppConfig.surveyURL = "";
    AppConfig.hostDescription = {
        default: "Welcome to the Secure Collaborative Document Editor!",
    };
    AppConfig.enableTemplates = false;
    AppConfig.enableHistory = false;
    AppConfig.loginSalt = '+g&~D02Tcw_x_ew0pv03Q+;%Fh9cU3)S,Fw9k@{.Ry,Ar)j_#y';
    AppConfig.minimumPasswordLength = 12;
    AppConfig.disableAnonymousStore = true;
    AppConfig.disableAnonymousPadCreation = true;
    AppConfig.disableFeedback = true;
    return AppConfig;
};


// Do not change code below
if (typeof(module) !== 'undefined' && module.exports) {
    module.exports = factory(
        require('../www/common/application_config_internal.js')
    );
} else if ((typeof(define) !== 'undefined' && define !== null) && (define.amd !== null)) {
    define(['/common/application_config_internal.js'], factory);
}

})();
