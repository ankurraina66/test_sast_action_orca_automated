import * as constants from './constants.js';

let serviceUrl = null;

function getProxyUrl() {
    return process.env.INPUT_PROXY_URL;
}

function getProxyPort() {
    return process.env.INPUT_PROXY_PORT;
}

function getProxyUser() {
    return process.env.INPUT_PROXY_USER;
}

function getProxyPwd() {
    return process.env.INPUT_PROXY_PWD;
}

function getServiceUrl() {
    if(!serviceUrl) {
        if(process.env.INPUT_SERVICE_URL) {
            serviceUrl = process.env.INPUT_SERVICE_URL;
        }
        else {
            let asoc_key = process.env.INPUT_ASOC_KEY;
            if(asoc_key && asoc_key.startsWith('eu-central')) {
                serviceUrl = constants.EU_SERVICE_URL
            }
            else {
                serviceUrl = constants.SERVICE_URL;
            }
        }
    }
    return serviceUrl;
}

function getScanUrl(scanId) {
    return `${getServiceUrl()}/main/myapps/${process.env.INPUT_APPLICATION_ID}/scans/${scanId}/scanOverview`;
}

function shouldDisableSSL() {
    return process.env.INPUT_ACCEPTSSL === 'true';
}

function isIncrementalScan() {
    return process.env.INPUT_INCREMENTAL_SCAN === 'true';
}

export default { getProxyUrl, getProxyPort, getProxyUser, getProxyPwd, getServiceUrl, getScanUrl, shouldDisableSSL, isIncrementalScan }
